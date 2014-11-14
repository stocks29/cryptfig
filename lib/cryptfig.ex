defmodule Cryptfig do
  require Logger
  use Application

  def start(_type, _args) do

    # Decrypt the applications
    decrypt_applications(
      decryptor(encrypt_settings()), decryptable_applications())

    # Only starting a supervisor to conform to OTP...
    children = []
    opts = [strategy: :one_for_one, name: Cryptfig.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp encrypt_settings() do
    dict = Application.get_env(:cryptfig, :encryption_env_vars)
    {
      env_value(dict[:secret_base_env]),
      env_value(dict[:encrypt_salt_env]),
      env_value(dict[:sign_salt_env])
    }
  end

  defp env_value(env_var) do
    value = System.get_env(env_var)
    log_nil(value, "#{env_var} is nil")
    value
  end

  defp log_nil(nil, log) do
    Logger.warn(log)
    nil
  end
  defp log_nil(notnil, _log) do
    notnil
  end

  defp decryptor({secret_base, encrypt_salt, sign_salt}) when is_binary(secret_base) and is_binary(encrypt_salt) and is_binary(sign_salt) do
    ezcryptex = Ezcryptex.new(secret_base, encrypt_salt, sign_salt) 
    fn(encrypted) -> Ezcryptex.decrypt!(ezcryptex, encrypted) end
  end

  defp decryptable_applications do
    Application.get_env(:cryptfig, :encrypted_apps, [])
  end

  defp decrypt_applications(decryptor, apps) do
    Enum.each(apps, fn(application) ->
      decrypt_application(decryptor, application)
    end) 
  end

  defp decrypt_application(decryptor, application) when is_function(decryptor) and is_atom(application) do
    Enum.each(Application.get_all_env(application), fn(pair) -> 
      handle_pair(decryptor, application, pair) 
    end)
  end

  defp handle_pair(decryptor, application, {key, value}) when is_function(decryptor) and is_atom(application) do
    new_value = handle_value(decryptor, value)
    :ok = Application.put_env(application, key, new_value, persistent: true)  
  end

  defp handle_value(decryptor, list) when is_function(decryptor) and is_list(list) do
    Logger.debug("handling list: #{inspect list}")
    Enum.map(list, fn(item) -> handle_value(decryptor, item) end)
  end
  defp handle_value(decryptor, {key, {:encrypted, encrypted}}) when is_function(decryptor) and is_binary(encrypted) do
    Logger.debug("decrypting: #{inspect encrypted}")
    {key, decryptor.(encrypted)}    
  end
  defp handle_value(decryptor, {:encrypted, encrypted}) when is_function(decryptor) and is_binary(encrypted) do
    Logger.debug("decrypting: #{inspect encrypted}")
    decryptor.(encrypted)
  end
  defp handle_value(_decryptor, {:encrypted, nonbinary}) do
    Logger.debug("not processing nonbinary: #{inspect nonbinary}")
    raise ArgumentException, message: "Encrypted value is not binary"
  end
  defp handle_value(_decryptor, nonencrypted) do
    Logger.debug("not processing non-encrypted: #{inspect nonencrypted}")
    nonencrypted
  end
end
