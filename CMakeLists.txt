cmake_minimum_required(VERSION 3.16)
project(TPLinkBypasser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ImGui paths
set(IMGUI_DIR "${CMAKE_SOURCE_DIR}/gui assets/dream imgui/imgui-master")
set(IMGUI_BACKENDS_DIR "${IMGUI_DIR}/backends")

# ImGui core sources
set(IMGUI_SOURCES
    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"
    "${IMGUI_DIR}/imgui_demo.cpp"
)

# ImGui backend sources (Win32 + DX11)
set(IMGUI_BACKEND_SOURCES
    "${IMGUI_BACKENDS_DIR}/imgui_impl_win32.cpp"
    "${IMGUI_BACKENDS_DIR}/imgui_impl_dx11.cpp"
)

# Application sources
set(APP_SOURCES
    "${CMAKE_SOURCE_DIR}/source/main.cpp"
    "${CMAKE_SOURCE_DIR}/source/bypasser.cpp"
)

# Create executable (WIN32 for WinMain entry point)
add_executable(${PROJECT_NAME} WIN32
    ${APP_SOURCES}
    ${IMGUI_SOURCES}
    ${IMGUI_BACKEND_SOURCES}
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    "${IMGUI_DIR}"
    "${IMGUI_BACKENDS_DIR}"
    "${CMAKE_SOURCE_DIR}/source"
)

# Link Windows libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    d3d11
    dxgi
    iphlpapi
    setupapi
    ole32
)

# Require admin (UAC manifest)
set_target_properties(${PROJECT_NAME} PROPERTIES
    LINK_FLAGS "/MANIFEST:EMBED /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    VS_DEBUGGER_REQUIRES_ADMIN TRUE
)
