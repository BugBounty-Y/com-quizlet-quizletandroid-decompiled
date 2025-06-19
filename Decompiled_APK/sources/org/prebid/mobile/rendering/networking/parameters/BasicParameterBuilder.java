package org.prebid.mobile.rendering.networking.parameters;

import java.util.Arrays;
import java.util.List;
import org.prebid.mobile.configuration.AdUnitConfiguration;

/* loaded from: classes3.dex */
public class BasicParameterBuilder extends ParameterBuilder {
    public static final String[] c = {"video/mp4", "video/3gpp", "video/webm", "video/mkv"};
    public static final int[] d = {2, 5};
    public static final List e = Arrays.asList(3, 5, 6);
    public final AdUnitConfiguration a;
    public final boolean b;

    public BasicParameterBuilder(AdUnitConfiguration adUnitConfiguration, boolean z) {
        this.a = adUnitConfiguration;
        this.b = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:173:0x040e  */
    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(org.prebid.mobile.rendering.networking.parameters.AdRequestInput r20) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1069
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.networking.parameters.BasicParameterBuilder.a(org.prebid.mobile.rendering.networking.parameters.AdRequestInput):void");
    }
}
