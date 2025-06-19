package com.amazon.device.ads;

import androidx.compose.ui.node.B;
import com.amazon.device.ads.DTBMetricReport;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONException;

/* loaded from: classes.dex */
public class DTBMetricsProcessor {
    static String ALERT_SDK_WRAPPING = "alert_sdk_wrapping";
    static String ALERT_SDK_WRAPPING_V2 = "alert_sdk_wrapping_v2";
    static String REPORT_LOAD_FAILURE = "fetch_failure";
    static String REPORT_LOAD_LATENCY = "fetch_latency";
    static String REPORT_LOST_BID = "lost_bid";
    static String REPORT_MEDIATION_LATENCY = "mediation_latency";
    private static String SIMPLE_TAG = "DTB_Metrics";
    private static DTBMetricsProcessor theProcessor = new DTBMetricsProcessor();
    private final Object lock = new Object();
    private List<DTBMetricReport> reportQueue = new ArrayList();
    private boolean running;

    private DTBMetricsProcessor() {
    }

    private void addReport(DTBMetricReport dTBMetricReport) {
        synchronized (this.reportQueue) {
            this.reportQueue.add(dTBMetricReport);
        }
    }

    private static String cacheBusterQueryString() {
        return AdRegistration.isTestMode() ? "?cb=0" : String.format("?cb=%d", Integer.valueOf((int) (Math.random() * 1.0E7d)));
    }

    private void dispenseReport() {
        if (isMainThread()) {
            DtbThreadService.getInstance().execute(new l(this, 3));
        } else {
            lambda$dispenseReport$1();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: dispenseReportImpl, reason: merged with bridge method [inline-methods] */
    public void lambda$dispenseReport$1() {
        synchronized (this.lock) {
            try {
                if (this.running) {
                    return;
                }
                this.running = true;
                while (this.reportQueue.size() > 0) {
                    DTBMetricReport dTBMetricReport = this.reportQueue.get(0);
                    try {
                        if (DTBMetricsConfiguration.getInstance().isTypeEnabled(dTBMetricReport.getType())) {
                            String completeURLForPixelsBasedOnReportURL = getCompleteURLForPixelsBasedOnReportURL(dTBMetricReport);
                            DtbLog.debug(SIMPLE_TAG, "Report URL:\n" + completeURLForPixelsBasedOnReportURL + "\nType:" + dTBMetricReport.getType());
                            String str = SIMPLE_TAG;
                            StringBuilder sb = new StringBuilder();
                            sb.append("Report:\n");
                            sb.append(dTBMetricReport);
                            DtbLog.debug(str, sb.toString());
                            new DtbHttpClient(completeURLForPixelsBasedOnReportURL).executeGET(60000);
                            removeFromQueue();
                            DtbLog.debug(SIMPLE_TAG, "Report Submission Success");
                        } else {
                            DtbLog.debug(SIMPLE_TAG, "Report type:" + dTBMetricReport.getType() + " is ignored");
                            removeFromQueue();
                        }
                    } catch (RuntimeException e) {
                        e = e;
                        DtbLog.warn("Exception:" + e.getMessage());
                        removeFromQueue();
                        com.amazon.aps.shared.a.e(1, 1, "Exception occurred while processing metric report", e);
                    } catch (MalformedURLException e2) {
                        DtbLog.warn("Malformed Exception:" + e2.getMessage());
                    } catch (IOException e3) {
                        DtbLog.warn("IOException:" + e3.getMessage());
                        DtbLog.debug(SIMPLE_TAG, "Report Submission Failure");
                    } catch (JSONException e4) {
                        e = e4;
                        DtbLog.warn("Exception:" + e.getMessage());
                        removeFromQueue();
                        com.amazon.aps.shared.a.e(1, 1, "Exception occurred while processing metric report", e);
                    }
                }
                this.running = false;
            } finally {
            }
        }
    }

    private String getCompleteURLForPixelsBasedOnReportURL(DTBMetricReport dTBMetricReport) throws UnsupportedEncodingException {
        String hostname = (dTBMetricReport.getHostname() == null || dTBMetricReport.getHostname().trim().length() == 0) ? DtbConstants.AAX_HOSTNAME : dTBMetricReport.getHostname();
        if (dTBMetricReport.getBidId() == null || dTBMetricReport.getBidId().trim().length() == 0) {
            return B.i(hostname, "/x/px/p/PH/", dTBMetricReport.toEncodedString(), cacheBusterQueryString());
        }
        return hostname + "/x/px/" + dTBMetricReport.getBidId() + "/" + dTBMetricReport.toEncodedString() + cacheBusterQueryString();
    }

    public static DTBMetricsProcessor getInstance() {
        return theProcessor;
    }

    private boolean isMainThread() {
        return DTBAdUtil.isMainThread();
    }

    private void removeFromQueue() {
        synchronized (this.reportQueue) {
            this.reportQueue.remove(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: submitExpiredReportImpl, reason: merged with bridge method [inline-methods] */
    public void lambda$submitExpiredReport$0(List<DTBMetricReport.BidWrapper> list) {
        Iterator<DTBMetricReport.BidWrapper> it2 = list.iterator();
        while (it2.hasNext()) {
            addReport(DTBMetricReport.reportWithBidIdAndType(it2.next(), REPORT_LOST_BID));
        }
        dispenseReport();
    }

    public void submitErrorReport(String str, Map<String, Object> map) {
        addReport(DTBMetricReport.reportWithTypeAndExtraProperties(str, map));
        dispenseReport();
    }

    public void submitExpiredReport(List<DTBMetricReport.BidWrapper> list) {
        if (isMainThread()) {
            DtbThreadService.getInstance().execute(new k(4, this, list));
        } else {
            lambda$submitExpiredReport$0(list);
        }
    }

    public void submitLatencyReportBidId(DTBMetricReport.BidWrapper bidWrapper, String str, int i) {
        addReport(DTBMetricReport.reportWithBidTypeLatency(bidWrapper, str, i));
        dispenseReport();
    }

    public void submitSimpleReportBidId(DTBMetricReport.BidWrapper bidWrapper, String str) {
        addReport(DTBMetricReport.reportWithBidIdAndType(bidWrapper, str));
        dispenseReport();
    }

    public void submitErrorReport(String str, Map<String, Object> map, DTBMetricReport.BidWrapper bidWrapper) {
        addReport(DTBMetricReport.reportWithTypeAndExtraProperties(str, map, bidWrapper));
        dispenseReport();
    }
}
