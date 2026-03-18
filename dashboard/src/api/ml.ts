// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — ML Model Status API hooks (O11).
 *
 * TanStack Query hooks for the ML model management dashboard:
 *   - useMLDashboard: aggregated single-call for global, tenant, retrain, inference data
 *   - useMLGlobalModel: global model info
 *   - useMLModels: per-tenant model version list
 *   - useMLRetrainStatus: retrain scheduler state
 *   - useMLRetrainHistory: historical retrain runs
 *   - useMLWorkerStats: retrain worker runtime
 *   - useMLFusionWeights: ensemble fusion weights
 *   - useMLShadowStatus: shadow mode evaluation
 *   - useMLAccuracy: rolling accuracy snapshot
 *   - useMLMetaAlerts: meta-detection alerts
 *   - useTriggerRetrain: manual retrain trigger
 *
 * @module api/ml
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import apiClient from "@/api/client"
import type {
  MLDashboardResponse,
  MLGlobalModelInfo,
  MLModelListResponse,
  MLRetrainStatus,
  MLRetrainHistoryResponse,
  MLRetrainResult,
  MLWorkerStats,
  MLFusionWeights,
  MLShadowStatus,
  MLAccuracySnapshot,
  MLMetaAlert,
  MLFeatureImportanceResponse,
  MLPredictionsResponse,
  MLTrainingSummary,
  MLConfusionMatrix,
} from "@/types"

/* ── Query Keys ────────────────────────────────────────────────────────────── */

export const ML_KEYS = {
  all: ["ml"] as const,
  dashboard: () => ["ml", "dashboard"] as const,
  globalModel: () => ["ml", "global-model"] as const,
  models: () => ["ml", "models"] as const,
  retrainStatus: () => ["ml", "retrain", "status"] as const,
  retrainHistory: () => ["ml", "retrain", "history"] as const,
  workerStats: () => ["ml", "retrain", "worker"] as const,
  fusion: () => ["ml", "fusion-weights"] as const,
  shadow: () => ["ml", "shadow"] as const,
  accuracy: () => ["ml", "accuracy"] as const,
  metaAlerts: () => ["ml", "meta-alerts"] as const,
  featureImportance: () => ["ml", "feature-importance"] as const,
  predictions: () => ["ml", "predictions"] as const,
  trainingSummary: () => ["ml", "training-summary"] as const,
  confusionMatrix: () => ["ml", "confusion-matrix"] as const,
}

/* ── Aggregated Dashboard ──────────────────────────────────────────────────── */

export function useMLDashboard() {
  return useQuery<MLDashboardResponse>({
    queryKey: ML_KEYS.dashboard(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/dashboard")
      return data
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
}

/* ── Individual Endpoints ──────────────────────────────────────────────────── */

export function useMLGlobalModel() {
  return useQuery<MLGlobalModelInfo>({
    queryKey: ML_KEYS.globalModel(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/global-model")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLModels() {
  return useQuery<MLModelListResponse>({
    queryKey: ML_KEYS.models(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/models")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLRetrainStatus() {
  return useQuery<MLRetrainStatus>({
    queryKey: ML_KEYS.retrainStatus(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/retrain/status")
      return data
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export function useMLRetrainHistory() {
  return useQuery<MLRetrainHistoryResponse>({
    queryKey: ML_KEYS.retrainHistory(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/retrain/history")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLWorkerStats() {
  return useQuery<MLWorkerStats>({
    queryKey: ML_KEYS.workerStats(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/retrain/worker")
      return data
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

export function useMLFusionWeights() {
  return useQuery<MLFusionWeights>({
    queryKey: ML_KEYS.fusion(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/fusion-weights")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLShadowStatus() {
  return useQuery<MLShadowStatus>({
    queryKey: ML_KEYS.shadow(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/shadow")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLAccuracy() {
  return useQuery<MLAccuracySnapshot>({
    queryKey: ML_KEYS.accuracy(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/accuracy")
      return data
    },
    staleTime: 30_000,
  })
}

export function useMLMetaAlerts() {
  return useQuery<MLMetaAlert[]>({
    queryKey: ML_KEYS.metaAlerts(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/meta-alerts")
      return data
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
}

/* ── ML Interpretability Endpoints ──────────────────────────────────────────── */

export function useMLFeatureImportance() {
  return useQuery<MLFeatureImportanceResponse>({
    queryKey: ML_KEYS.featureImportance(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/feature-importance")
      return data
    },
    staleTime: 60_000,
  })
}

export function useMLPredictions(limit = 100) {
  return useQuery<MLPredictionsResponse>({
    queryKey: ML_KEYS.predictions(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/predictions", { params: { limit } })
      return data
    },
    staleTime: 10_000,
    refetchInterval: 30_000,
  })
}

export function useMLTrainingSummary() {
  return useQuery<MLTrainingSummary>({
    queryKey: ML_KEYS.trainingSummary(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/training-summary")
      return data
    },
    staleTime: 60_000,
  })
}

export function useMLConfusionMatrix() {
  return useQuery<MLConfusionMatrix>({
    queryKey: ML_KEYS.confusionMatrix(),
    queryFn: async () => {
      const { data } = await apiClient.get("/ml/confusion-matrix")
      return data
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
}

/* ── Manual Retrain Trigger ────────────────────────────────────────────────── */

export function useTriggerRetrain() {
  const qc = useQueryClient()
  return useMutation<MLRetrainResult, Error>({
    mutationFn: async () => {
      const { data } = await apiClient.post("/ml/retrain/trigger")
      return data
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ML_KEYS.retrainStatus() })
      qc.invalidateQueries({ queryKey: ML_KEYS.retrainHistory() })
      qc.invalidateQueries({ queryKey: ML_KEYS.models() })
      qc.invalidateQueries({ queryKey: ML_KEYS.dashboard() })
    },
  })
}
