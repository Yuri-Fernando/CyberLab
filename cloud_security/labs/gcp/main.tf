# cloud_security/labs/gcp/main.tf
#
# Lab didático de infraestrutura-como-codigo propositalmente mal configurada
# para GCP. Nunca aplicado contra um projeto real — alvo apenas de scan
# estatico local (Checkov / trivy config). Nenhuma credencial GCP e usada
# ou necessaria.

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
  }
}

provider "google" {
  project = "cyberlab-misconfig-lab"
  region  = "us-central1"
}

# --- Misconfig 1: bucket GCS publico ---
resource "google_storage_bucket" "public_bucket" {
  name     = "cyberlab-misconfig-public-bucket"
  location = "US"

  uniform_bucket_level_access = false

  versioning {
    enabled = false
  }
}

resource "google_storage_bucket_iam_binding" "public_binding" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}

# --- Misconfig 2: firewall rule aberta a 0.0.0.0/0 em porta sensivel ---
resource "google_compute_firewall" "open_firewall" {
  name    = "cyberlab-misconfig-open-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"
}

# --- Misconfig 3: service account com role excessivo (roles/owner no projeto) ---
resource "google_service_account" "overprivileged_sa" {
  account_id   = "cyberlab-misconfig-sa"
  display_name = "CyberLab misconfig lab service account"
}

resource "google_project_iam_member" "overprivileged_binding" {
  project = "cyberlab-misconfig-lab"
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.overprivileged_sa.email}"
}
