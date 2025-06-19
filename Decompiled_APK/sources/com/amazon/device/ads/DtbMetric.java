package com.amazon.device.ads;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'AAX_BID_TIME' uses external variables
	at jadx.core.dex.visitors.EnumVisitor.createEnumFieldByConstructor(EnumVisitor.java:451)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByRegister(EnumVisitor.java:395)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromFilledArray(EnumVisitor.java:324)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromInsn(EnumVisitor.java:262)
	at jadx.core.dex.visitors.EnumVisitor.convertToEnum(EnumVisitor.java:151)
	at jadx.core.dex.visitors.EnumVisitor.visit(EnumVisitor.java:100)
 */
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* loaded from: classes.dex */
final class DtbMetric {
    private static final /* synthetic */ DtbMetric[] $VALUES;
    public static final DtbMetric AAX_BID_TIME;
    public static final DtbMetric AAX_NETWORK_FAILURE;
    public static final DtbMetric AAX_PUNTED;
    public static final DtbMetric ADSERVER_ADLOAD_FAILURE;
    public static final DtbMetric BANNER_ADSERVER_TIME;
    public static final DtbMetric BANNER_TOTAL_LOAD_TIME;
    public static final DtbMetric CONFIG_DOWNLOAD_LATENCY;
    public static final DtbMetric INTERSTITIAL_ADSERVER_TIME;
    public static final DtbMetric INTERSTITIAL_TOTAL_LOAD_TIME;
    public static final DtbMetric SIS_COUNTER_IDENTIFIED_DEVICE_CHANGED;
    public static final DtbMetric SIS_LATENCY_REGISTER_EVENT;
    public static final DtbMetric SIS_LATENCY_UPDATE_DEVICE_INFO;
    private final String aaxName3g;
    private final String aaxNameWifi;
    private final DtbMetricType metricType;

    public enum DtbMetricType {
        COUNTER,
        TIMER
    }

    static {
        DtbMetricType dtbMetricType = DtbMetricType.TIMER;
        DtbMetric dtbMetric = new DtbMetric("AAX_BID_TIME", 0, "dabtw", "dabt3", dtbMetricType);
        AAX_BID_TIME = dtbMetric;
        DtbMetricType dtbMetricType2 = DtbMetricType.COUNTER;
        DtbMetric dtbMetric2 = new DtbMetric("AAX_PUNTED", 1, "dapw", "dap3", dtbMetricType2);
        AAX_PUNTED = dtbMetric2;
        DtbMetric dtbMetric3 = new DtbMetric("AAX_NETWORK_FAILURE", 2, "danfw", "danf3", dtbMetricType2);
        AAX_NETWORK_FAILURE = dtbMetric3;
        DtbMetric dtbMetric4 = new DtbMetric("BANNER_ADSERVER_TIME", 3, "dbastw", "dbast3", dtbMetricType);
        BANNER_ADSERVER_TIME = dtbMetric4;
        DtbMetric dtbMetric5 = new DtbMetric("INTERSTITIAL_ADSERVER_TIME", 4, "diastw", "diast3", dtbMetricType);
        INTERSTITIAL_ADSERVER_TIME = dtbMetric5;
        DtbMetric dtbMetric6 = new DtbMetric("ADSERVER_ADLOAD_FAILURE", 5, "dasfw", "dasf3", dtbMetricType2);
        ADSERVER_ADLOAD_FAILURE = dtbMetric6;
        DtbMetric dtbMetric7 = new DtbMetric("BANNER_TOTAL_LOAD_TIME", 6, "dbtltw", "dbtlt3", dtbMetricType);
        BANNER_TOTAL_LOAD_TIME = dtbMetric7;
        DtbMetric dtbMetric8 = new DtbMetric("INTERSTITIAL_TOTAL_LOAD_TIME", 7, "ditltw", "ditlt3", dtbMetricType);
        INTERSTITIAL_TOTAL_LOAD_TIME = dtbMetric8;
        DtbMetric dtbMetric9 = new DtbMetric("CONFIG_DOWNLOAD_LATENCY", 8, "acl", "acl", dtbMetricType);
        CONFIG_DOWNLOAD_LATENCY = dtbMetric9;
        DtbMetric dtbMetric10 = new DtbMetric("SIS_LATENCY_UPDATE_DEVICE_INFO", 9, "sul", "sul", dtbMetricType);
        SIS_LATENCY_UPDATE_DEVICE_INFO = dtbMetric10;
        DtbMetric dtbMetric11 = new DtbMetric("SIS_COUNTER_IDENTIFIED_DEVICE_CHANGED", 10, "sid", "sid", dtbMetricType2);
        SIS_COUNTER_IDENTIFIED_DEVICE_CHANGED = dtbMetric11;
        DtbMetric dtbMetric12 = new DtbMetric("SIS_LATENCY_REGISTER_EVENT", 11, "srel", "srel", dtbMetricType);
        SIS_LATENCY_REGISTER_EVENT = dtbMetric12;
        $VALUES = new DtbMetric[]{dtbMetric, dtbMetric2, dtbMetric3, dtbMetric4, dtbMetric5, dtbMetric6, dtbMetric7, dtbMetric8, dtbMetric9, dtbMetric10, dtbMetric11, dtbMetric12};
    }

    private DtbMetric(String str, int i, String str2, String str3, DtbMetricType dtbMetricType) {
        this.aaxNameWifi = str2;
        this.aaxName3g = str3;
        this.metricType = dtbMetricType;
    }

    public static DtbMetric valueOf(String str) {
        return (DtbMetric) Enum.valueOf(DtbMetric.class, str);
    }

    public static DtbMetric[] values() {
        return (DtbMetric[]) $VALUES.clone();
    }

    public String getAAXName() {
        return DtbNetworkState.INSTANCE.isWifiConnection() ? this.aaxNameWifi : this.aaxName3g;
    }

    public DtbMetricType getMetricType() {
        return this.metricType;
    }

    @Override // java.lang.Enum
    public String toString() {
        return "[" + getAAXName() + ", " + getMetricType() + "]";
    }
}
