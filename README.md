# Mythos Driver

Projeto de driver de kernel para Windows (AntiCheatDriver) com ferramentas de assinatura e teste.

## Visao geral

O `AntiCheatDriver` e um driver de kernel em modo kernel (WDM/KMDF) para Windows x64 que monitora a integridade de processos protegidos. Ele registra eventos de criacao de processos/threads, carregamento de imagens (modulos/DLLs) e executa varreduras de memoria, gerando violacoes quando detecta comportamento suspeito (modulos de cheat, hooks de API, injecao de codigo, tampering, debugger).

### Como funciona

1. Inicializacao: `DriverEntry` cria o dispositivo e registra callbacks de processo, thread e image load.
2. Monitoramento: callbacks do kernel notificam criacao/remocao de processos e carregamento de modulos.
3. Rastreamento: processos protegidos sao mantidos em lista com modulos e hashes.
4. Deteccao: varredura periodica (timer DPC) verifica integridade de modulos, hooks e regioes de memoria.
5. Violacoes: eventos sao armazenados em buffer circular e expostos via IOCTL para um cliente user-mode.
6. Controle: IOCTLs permitem registrar/desregistrar processos, escanear memoria, consultar violacoes e ajustar configuracao (AC_CONFIG).

### Interface IOCTL

- `IOCTL_AC_REGISTER_PROCESS` - registra processo para monitoramento
- `IOCTL_AC_UNREGISTER_PROCESS` - remove processo do monitoramento
- `IOCTL_AC_SCAN_MEMORY` - varre regiao de memoria de um processo
- `IOCTL_AC_QUERY_INTEGRITY` - consulta integridade de modulos
- `IOCTL_AC_GET_VIOLATIONS` - obtem violacoes registradas
- `IOCTL_AC_SET_CONFIG` - atualiza configuracao do driver

### Estrutura do repositorio

- `AntiCheatDriver/` - codigo do driver (src/, include/, CMakeLists.txt)
- `BasicTest/` - cliente de teste (.NET) com testes de IOCTL
- `DriverSigner/` - ferramenta de assinatura de arquivos PE via signtool
- `SignedDrivers/` - driver assinado para distribuicao/teste
- `*.ps1` - verificacao/exportacao de certificados

## Compilacao do driver

Requisitos: Windows, Visual Studio com workload C++, WDK 10.0.26100.0, CMake 3.20+.

```powershell
cd AntiCheatDriver
cmake -S . -B build -A x64
cmake --build build --config Release
```

Saida: `build/Release/AntiCheatDriver.sys`.

Para assinar automaticamente no build:

```powershell
cmake -S . -B build -A x64 -DSIGN_DRIVER=ON
cmake --build build --config Release
```

(requer signtool no PATH).

## Assinatura de driver

Use `DriverSigner` para assinar `.sys`/`.exe`/`.dll` com um certificado PFX:

```powershell
dotnet run --project DriverSigner -- --file AntiCheatDriver.sys --cert TestDriverCert.pfx --password <senha> --verify
```

## Teste

1. Habilitar test signing: `bcdedit /set testsigning on` e reiniciar.
2. Carregar o driver: `sc create AntiCheatDriver type= kernel binPath= <caminho>\AntiCheatDriver.sys` e `sc start AntiCheatDriver`.
3. Executar `BasicTest` para validar IOCTLs (o teste reporta se o dispositivo nao estiver carregado).

## Melhorias implementadas

- Build Debug/Release corrigido (conflito /O2 vs /RTC1).
- Migracao de ExAllocatePoolWithTag para ExAllocatePool2.
- Regras de detecao revisadas (basename, case-insensitive, remocao de falsos positivos).
- Testes IOCTL adicionados ao BasicTest.
- Documentacao de IOCTLs no header.
- Opcao SIGN_DRIVER no CMake e CI no GitHub Actions.
