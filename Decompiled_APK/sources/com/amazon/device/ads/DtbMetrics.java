package com.amazon.device.ads;

import com.amazon.device.ads.DtbMetric;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
class DtbMetrics implements Cloneable {
    private final String LOG_TAG = "DtbMetrics";
    private volatile Map<DtbMetric, Long> collectedMetrics = new EnumMap(DtbMetric.class);
    private volatile Map<DtbMetric, Long> tempTimer = new EnumMap(DtbMetric.class);
    private String instPxlUrl = null;

    public String getInstPxlUrl() {
        return this.instPxlUrl;
    }

    public int getMetricsCount() {
        return this.collectedMetrics.size();
    }

    public void incrementMetric(DtbMetric dtbMetric) {
        if (dtbMetric == null || dtbMetric.getMetricType() != DtbMetric.DtbMetricType.COUNTER) {
            throw new IllegalArgumentException("Either metric is null or metric type is not counter.");
        }
        if (this.collectedMetrics.get(dtbMetric) == null) {
            this.collectedMetrics.put(dtbMetric, 0L);
        }
        this.collectedMetrics.put(dtbMetric, Long.valueOf(this.collectedMetrics.get(dtbMetric).longValue() + 1));
    }

    public boolean isStarted(DtbMetric dtbMetric) {
        return this.tempTimer.containsKey(dtbMetric);
    }

    public void reset() {
        this.collectedMetrics.clear();
        this.tempTimer.clear();
    }

    public void resetMetric(DtbMetric dtbMetric) {
        try {
            this.collectedMetrics.remove(dtbMetric);
            this.tempTimer.remove(dtbMetric);
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to reset Metrics ", e);
        }
    }

    public void setInstPxlUrl(String str) {
        int iIndexOf;
        if (str != null && (iIndexOf = str.indexOf("://")) != -1) {
            str = str.substring(iIndexOf + 3);
        }
        this.instPxlUrl = str;
    }

    public void startTimer(DtbMetric dtbMetric) {
        if (dtbMetric != null) {
            try {
                if (dtbMetric.getMetricType() == DtbMetric.DtbMetricType.TIMER) {
                    if (this.collectedMetrics.get(dtbMetric) == null) {
                        this.tempTimer.put(dtbMetric, Long.valueOf(System.currentTimeMillis()));
                        return;
                    }
                    throw new IllegalArgumentException(dtbMetric + " is already set, your operation is trying to override a value.");
                }
            } catch (Exception e) {
                com.amazon.aps.shared.a.e(1, 1, "Failed to Start timer ", e);
                return;
            }
        }
        throw new IllegalArgumentException("Either metric is null or metric type is not timer.");
    }

    public void stopTimer(DtbMetric dtbMetric) {
        if (dtbMetric != null) {
            try {
                if (dtbMetric.getMetricType() != DtbMetric.DtbMetricType.COUNTER) {
                    if (this.tempTimer.get(dtbMetric) == null) {
                        throw new IllegalArgumentException("You are trying to stop a metric, which is not yet started: " + dtbMetric);
                    }
                    if (this.collectedMetrics.get(dtbMetric) == null) {
                        this.collectedMetrics.put(dtbMetric, Long.valueOf(System.currentTimeMillis() - this.tempTimer.get(dtbMetric).longValue()));
                        this.tempTimer.remove(dtbMetric);
                        return;
                    } else {
                        throw new IllegalArgumentException(dtbMetric + " is already set, your operation is trying to override a value.");
                    }
                }
            } catch (Exception e) {
                com.amazon.aps.shared.a.e(1, 1, "Failed to stop timer ", e);
                return;
            }
        }
        throw new IllegalArgumentException("Either metric is null or metric type is not timer.");
    }

    public String toString() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("c", "dtbm");
            for (Map.Entry<DtbMetric, Long> entry : this.collectedMetrics.entrySet()) {
                jSONObject.put(entry.getKey().getAAXName(), entry.getValue());
            }
        } catch (JSONException e) {
            DtbLog.debug("Error while adding values to JSON object: " + e.getLocalizedMessage());
        }
        return jSONObject.toString();
    }

    public String toURLEncodedString() {
        return DtbCommonUtils.getURLEncodedString(toString());
    }

    /* renamed from: clone, reason: merged with bridge method [inline-methods] */
    public DtbMetrics m9clone() {
        DtbMetrics dtbMetrics = new DtbMetrics();
        dtbMetrics.collectedMetrics.putAll(this.collectedMetrics);
        dtbMetrics.tempTimer.putAll(this.tempTimer);
        dtbMetrics.instPxlUrl = this.instPxlUrl;
        return dtbMetrics;
    }

    public static class Submitter {
        public static final Submitter INSTANCE = new Submitter();
        private final String LOG_TAG = Submitter.class.getSimpleName();
        private final Queue<DtbMetrics> metricsQueue = new ConcurrentLinkedQueue();

        private Submitter() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void lambda$submitMetrics$0() {
            DtbLog.debug("Starting metrics submission..");
            submitMetrics();
            DtbLog.debug("Metrics submission thread complete.");
        }

        public void submitMetrics(DtbMetrics dtbMetrics) {
            if (dtbMetrics.getMetricsCount() > 0) {
                this.metricsQueue.add(dtbMetrics.m9clone());
                dtbMetrics.reset();
                DtbLog.debug("Scheduling metrics submission in background thread.");
                DtbThreadService.getInstance().schedule(new l(this, 0));
                DtbLog.debug("Dispatched the metrics submit task on a background schedule thread.");
            }
        }

        private void submitMetrics() {
            Iterator<DtbMetrics> it2 = this.metricsQueue.iterator();
            int i = 0;
            while (it2.hasNext()) {
                DtbMetrics next = it2.next();
                i++;
                DtbLog.debug("Starting metrics submission - Sequence " + i);
                if (next.getInstPxlUrl() == null) {
                    it2.remove();
                    DtbLog.debug("No metric url found- Sequence " + i + ", skipping..");
                } else {
                    String str = next.getInstPxlUrl() + next.toURLEncodedString();
                    DtbLog.debug("Metrics URL:" + str);
                    try {
                        DtbHttpClient dtbHttpClient = new DtbHttpClient(str);
                        dtbHttpClient.setUseSecure(DtbDebugProperties.getIsSecure(true));
                        dtbHttpClient.executeGET(60000);
                        if (dtbHttpClient.isHttpStatusCodeOK()) {
                            DtbLog.debug("Metrics submitted- Sequence " + i);
                            it2.remove();
                        } else {
                            DtbLog.debug("Metrics submission failed- Sequence " + i + ", response invalid");
                            return;
                        }
                    } catch (Exception e) {
                        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Metrics submission failed- Sequence ", ", encountered error:");
                        sbV.append(e.toString());
                        DtbLog.debug(sbV.toString());
                        return;
                    }
                }
            }
        }
    }
}
