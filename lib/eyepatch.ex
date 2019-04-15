defmodule Eyepatch do
  use GenServer

  defstruct caller_pid: nil,
            inet_dns_response: nil,
            inet6_dns_response: nil,
            inet_connect_result: nil,
            inet6_connect_result: nil,
            uri: nil,
            request_ipv4_fn: nil,
            request_ipv6_fn: nil,
            getaddrs: nil,
            headers: []

  # https://tools.ietf.org/html/rfc8305

  # The recommended value for the Resolution Delay is 50 milliseconds.
  @resolution_delay 50

  # "One recommended value for a default [connection attempt] delay is 250 milliseconds."
  # TODO we use a value of 1500 not because we deem this value ideal, but because it's easier to implement.
  # A better happy eyeballs implementation would use a lower value (e.g. the recommended 250 milliseconds), without
  # failing after the connection_attempt_delay has been exceeded: Exceeding the connection_attempt_delay only means
  # we should start a new attempt in parallel to the current attempt, not that we should consider the
  # current attempt failed.
  @connection_attempt_delay 1500

  @success_ipv4_msg "Successfully connected via IPv4."


  require Logger

  @moduledoc """
  Dual stack connection establishment. Hopefully, this will one day be extended to a full
  happy eyeballs implementation.
  """

  def resolve(url, request_ipv4_fn, request_ipv6_fn, getaddrs \\ &:inet.getaddrs/2, headers \\ []) do
    {:ok, _pid} = start_link(url, request_ipv4_fn, request_ipv6_fn, getaddrs, headers, self())

    receive do
      {:eyepatch, result} ->
        Logger.debug("#{inspect(result)}")
        result
    end
  end

  def start_link(url, request_ipv4_fn, request_ipv6_fn, getaddrs, headers, caller_pid) do
    state =
      initial_state(url, request_ipv4_fn, request_ipv6_fn, getaddrs, headers, caller_pid)

    GenServer.start_link(__MODULE__, state)
  end

  defp initial_state(url, request_ipv4_fn, request_ipv6_fn, getaddrs, headers, caller_pid) do
    %Eyepatch{
      inet_dns_response: nil,
      inet6_dns_response: nil,
      inet_connect_result: nil,
      inet6_connect_result: nil,
      uri: URI.parse(url),
      request_ipv4_fn: request_ipv4_fn,
      request_ipv6_fn: request_ipv6_fn,
      getaddrs: getaddrs,
      headers: headers,
      caller_pid: caller_pid
    }
  end

  def init(state = %Eyepatch{}) do
    # When a client has both IPv4 and IPv6 connectivity and is trying to
    # establish a connection with a named host, it needs to send out both
    # AAAA and A DNS queries.  Both queries SHOULD be made as soon after
    # one another as possible, with the AAAA query made first and
    # immediately followed by the A query.

    protocols = [:inet6, :inet]

    Logger.debug("Starting DNS resolution for both protocols for URI #{inspect(state.uri)}")

    Enum.each(protocols, fn protocol ->
      Task.async(fn ->
        case state.getaddrs.(to_charlist(state.uri.host), protocol) do
          {:ok, [ip_address | _ignored]} ->
            # TODO for now, we just ignore all results except for the first.
            Logger.debug(
              "Successful DNS resolution for #{protocol}: #{state.uri.host} -> #{
                :inet.ntoa(ip_address)
              }"
            )

            {:dns_reply, {protocol, {:ok, ip_address}}}

          {:error, reason} ->
            Logger.warn("DNS resolution failed for #{protocol} for uri #{state.uri}")
            {:dns_reply, {protocol, {:error, reason}}}
        end
      end)
    end)

    {:ok, state}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, {:ok, ip_address}}}},
        state = %Eyepatch{inet6_dns_response: {:error, _reason}}
      ) do
    Logger.debug(
      "Received inet DNS response after inet6 DNS failure. Will attempt to connect via inet."
    )

    result = state.request_ipv4_fn.(state.uri, ip_address, @connection_attempt_delay, [])

    case result do
      {:ok, _} ->
        Logger.debug(@success_ipv4_msg)

      {:error, _reason} ->
        Logger.error("IPv4 Connection failed, IPv6 DNS failed: We're out of options.")
    end

    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, {:ok, ip_address}}}},
        state = %Eyepatch{inet6_connect_result: {:error, _reason}, inet_connect_result: nil}
      ) do
    Logger.debug(
      "Received inet DNS response after inet6 connection failure. Will attempt to connect via inet."
    )

    result = state.request_ipv4_fn.(state.uri, ip_address, @connection_attempt_delay, [])

    case result do
      {:ok, _} ->
        Logger.debug(@success_ipv4_msg)

      {:error, _reason} ->
        Logger.error("IPv4 Connection failed, IPv6 DNS failed: We're out of options.")
    end

    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, result = {:error, _reason1}}}},
        state = %Eyepatch{inet6_connect_result: {:error, _reason2}}
      ) do
    Logger.error("IPv4 DNS failed, IPv6 connection failed: We're out of options.")
    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, reply = {:ok, _ip_address}}}},
        state = %Eyepatch{inet6_dns_response: nil}
      ) do
    # If a positive A response is received first due to reordering, the client SHOULD
    # wait a short time for the AAAA response to ensure that preference is
    # given to IPv6 (it is common for the AAAA response to follow the A
    # response by a few milliseconds). This delay will be referred to as
    # the "Resolution Delay".
    Logger.debug(
      "IPv4 DNS resolution successful: Will connect via IPv4 unless IPv6 succeeds shortly."
    )

    :erlang.send_after(@resolution_delay, self(), :inet6_deadline_exceeded)
    {:noreply, %{state | inet_dns_response: reply}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet6, {:error, reason}}}},
        state = %Eyepatch{inet_dns_response: nil}
      ) do
    Logger.debug("IPv6 DNS resolution failed: #{reason}. Will wait for IPv4 DNS reply.")
    {:noreply, %{state | inet6_dns_response: {:error, reason}}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, {:error, reason}}}},
        state = %Eyepatch{inet6_dns_response: nil}
      ) do
    Logger.debug("IPv4 DNS resolution failed: #{reason}. Will wait for IPv6 DNS reply.")
    {:noreply, %{state | inet_dns_response: {:error, reason}}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet6, {:error, _reason}}}},
        state = %Eyepatch{inet_dns_response: {:ok, ip_address}, inet_connect_result: nil}
      ) do
    Logger.debug("IPv6 DNS resolution failed, will attempt to connect via IPv4.")
    result = state.request_ipv4_fn.(state.uri, ip_address, @connection_attempt_delay, [])

    case result do
      {:ok, _} ->
        Logger.debug(@success_ipv4_msg)

      {:error, _reason} ->
        Logger.error("IPv4 connection failed, IPv6 DNS resolution failed: We're out of options.")
    end

    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet, result = {:error, _}}}},
        state = %Eyepatch{inet6_dns_response: {:error, _}}
      ) do
    Logger.error("Both IPv4 and IPv6 DNS resolution failed: We're out of options.")
    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet6, result = {:error, _}}}},
        state = %Eyepatch{inet_dns_response: {:error, _}}
      ) do
    Logger.error("Both IPv4 and IPv6 DNS resolution failed: We're out of options.")
    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        :inet6_deadline_exceeded,
        state = %Eyepatch{inet_dns_response: {:ok, ip_address}}
      ) do
    Logger.debug(
      "IPv6 DNS has not succeeded within the resolution delay. Will attempt to connect via IPv4."
    )

    result = state.request_ipv4_fn.(state.uri, ip_address, @connection_attempt_delay, [])

    case result do
      {:ok, _} ->
        Logger.debug(@success_ipv4_msg)

      {:error, _reason} ->
        Logger.error("IPv4 connection failed, IPv6 DNS response not received yet.")
        # TODO there's still a chance that we receive the inet6 DNS response. Read the RFC to
        # decide how to handle this case.
    end

    {:stop, :normal, {state.caller_pid, result}}
  end

  def handle_info(
        {_, {:dns_reply, {:inet6, {:ok, ip_address}}}},
        state = %Eyepatch{inet6_dns_response: nil}
      ) do
    Logger.debug("IPv6 DNS resolution successful: Will connect via IPv6.")
    result = state.request_ipv6_fn.(state.uri, ip_address, @connection_attempt_delay, [])

    case result do
      {:ok, _} ->
        Logger.debug("Succesfully connected via IPv6")
        {:stop, :normal, {state.caller_pid, result}}

      {:error, reason} ->
        case {state.inet_dns_response, state.inet_connect_result} do
          {nil, nil} ->
            Logger.error(
              "IPv6 Connection failed. Will wait for IPv4 DNS response to connect via IPv4."
            )

            {:noreply,
             %{
               state
               | inet6_dns_response: {:ok, ip_address},
                 inet6_connect_result: {:error, reason}
             }}

          {{:ok, ip_address}, nil} ->
            Logger.error("IPv6 Connection failed. Will attempt to connect via IPv4.")

            ipv4_result =
              state.request_ipv4_fn.(state.uri, ip_address, @connection_attempt_delay, [])

            case ipv4_result do
              {:ok, _} ->
                Logger.debug("Succesfully connected via IPv6.")
                {:stop, :normal, {state.caller_pid, ipv4_result}}

              {:error, _reason} ->
                Logger.debug(
                  "IPv4 connection failed after IPv6 connection failed. We're out of options."
                )

                {:stop, :normal, {state.caller_pid, ipv4_result}}
            end

          {result = {:error, _}, nil} ->
            Logger.debug(
              "IPv4 connection failed after IPv6 DNS resolution failed. We're out of options."
            )

            {:stop, :normal, {state.caller_pid, result}}
        end
    end
  end

  def handle_info({:DOWN, _ref, :process, _pid, :normal}, state) do
    {:noreply, state}
  end

  def terminate(_reason, {caller_pid, result}) do
    send(caller_pid, {:eyepatch, result})
  end
end
