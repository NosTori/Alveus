#pragma once

#include "fernon.h"

FERNON_NAMESPACE_BEGIN

//////////////////////////////////////////////////////////////////////
// GF 3904

#define GF_3904_NostaleClientX_SECTION_CODE_RVA                             0x1000
#define GF_3904_NostaleClientX_SECTION_CODE_START_ADDRESS                   0x400
#define GF_3904_NostaleClientX_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET    GF_3904_NostaleClientX_SECTION_CODE_RVA - GF_3904_NostaleClientX_SECTION_CODE_START_ADDRESS
#define GF_3904_NostaleClient_SECTION_CODE_RVA                              0x1000
#define GF_3904_NostaleClient_SECTION_CODE_START_ADDRESS                    0x400
#define GF_3904_NostaleClient_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET     GF_3904_NostaleClient_SECTION_CODE_RVA - GF_3904_NostaleClient_SECTION_CODE_START_ADDRESS

#ifdef GF_3904
    #define NostaleClientX_SECTION_CODE_RVA GF_3904_NostaleClientX_SECTION_CODE_RVA
    #define NostaleClientX_SECTION_CODE_START_ADDRESS GF_3904_NostaleClientX_SECTION_CODE_START_ADDRESS
    #define NostaleClientX_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET GF_3904_NostaleClientX_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET
    #define NostaleClient_SECTION_CODE_RVA GF_3904_NostaleClient_SECTION_CODE_RVA
    #define NostaleClient_SECTION_CODE_START_ADDRESS GF_3904_NostaleClient_SECTION_CODE_START_ADDRESS
    #define NostaleClient_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET GF_3904_NostaleClient_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET
#endif

//////////////////////////////////////////////////////////////////////

FERNON_NAMESPACE_END
