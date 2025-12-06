#!/bin/sh

# Setup Pod Security Admission (PSA)
kubectl label namespace secure-ns \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/audit-version=latest \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/warn-version=latest

# Patch container security in deployment
kubectl patch deployment --patch-file patch.yml

# Download a network plugin
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
# Apply network policy
kubectl apply -f network-pol.yml
