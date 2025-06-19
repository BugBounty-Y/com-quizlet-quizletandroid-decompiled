package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class G3 implements F3 {
    public static final F1 a;
    public static final F1 b;
    public static final F1 c;
    public static final F1 d;
    public static final F1 e;
    public static final F1 f;
    public static final F1 g;
    public static final F1 h;

    static {
        androidx.appcompat.app.K k = new androidx.appcompat.app.K(B1.a(), true, true);
        k.Q("measurement.rb.attribution.ad_campaign_info", true);
        k.Q("measurement.rb.attribution.service.bundle_on_backgrounded", true);
        a = k.Q("measurement.rb.attribution.client2", true);
        k.Q("measurement.rb.attribution.dma_fix", true);
        b = k.Q("measurement.rb.attribution.followup1.service", false);
        k.Q("measurement.rb.attribution.client.get_trigger_uris_async", true);
        c = k.Q("measurement.rb.attribution.service.trigger_uris_high_priority", true);
        k.Q("measurement.rb.attribution.index_out_of_bounds_fix", true);
        d = k.Q("measurement.rb.attribution.service.enable_max_trigger_uris_queried_at_once", true);
        e = k.Q("measurement.rb.attribution.retry_disposition", false);
        f = k.Q("measurement.rb.attribution.service", true);
        g = k.Q("measurement.rb.attribution.enable_trigger_redaction", true);
        h = k.Q("measurement.rb.attribution.uuid_generation", true);
        k.O(0L, "measurement.id.rb.attribution.retry_disposition");
        k.Q("measurement.rb.attribution.improved_retry", true);
    }
}
