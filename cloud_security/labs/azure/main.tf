# cloud_security/labs/azure/main.tf
#
# Lab didático de infraestrutura-como-codigo propositalmente mal configurada
# para Azure. Nunca aplicado contra uma subscription real — alvo apenas de
# scan estatico local (Checkov / trivy config). Nenhuma credencial Azure
# e usada ou necessaria.

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  skip_provider_registration = true
}

resource "azurerm_resource_group" "lab" {
  name     = "cyberlab-misconfig-rg"
  location = "eastus"
}

# --- Misconfig 1: Storage Account com acesso publico habilitado ---
resource "azurerm_storage_account" "public_storage" {
  name                     = "cyberlabmisconfigsa"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true
  min_tls_version                 = "TLS1_0"

  blob_properties {
    delete_retention_policy {
      days = 0
    }
  }
}

# --- Misconfig 2: NSG aberto a 0.0.0.0/0 em porta sensivel ---
resource "azurerm_network_security_group" "open_nsg" {
  name                = "cyberlab-misconfig-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  security_rule {
    name                       = "AllowSSHFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowRDPFromAnywhere"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# --- Misconfig 3: Key Vault sem soft-delete / purge protection ---
resource "azurerm_key_vault" "no_soft_delete" {
  name                = "cyberlab-misconfig-kv"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  soft_delete_retention_days = 7
  purge_protection_enabled    = false

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}
