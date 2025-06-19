package com.snowplowanalytics.core.tracker;

import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends com.snowplowanalytics.snowplow.payload.a {
    public static final /* synthetic */ int b = 0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(long j, long j2, String installReferrer, boolean z) {
        super("iglu:com.android.installreferrer.api/referrer_details/jsonschema/1-0-0", V.f(new Pair("installReferrer", installReferrer), new Pair("referrerClickTimestamp", j > 0 ? E6.c(j * 1000) : null), new Pair("installBeginTimestamp", j2 > 0 ? E6.c(j2 * 1000) : null), new Pair("googlePlayInstantParam", Boolean.valueOf(z))));
        Intrinsics.checkNotNullParameter(installReferrer, "installReferrer");
    }
}
