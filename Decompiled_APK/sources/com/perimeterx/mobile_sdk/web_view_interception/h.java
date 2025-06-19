package com.perimeterx.mobile_sdk.web_view_interception;

import android.webkit.ValueCallback;
import androidx.lifecycle.u0;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class h implements ValueCallback {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ h(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.webkit.ValueCallback
    public final void onReceiveValue(Object obj) {
        String str = (String) obj;
        switch (this.a) {
            case 0:
                ((u0) this.b).invoke(Boolean.valueOf(Intrinsics.b(str, "\"ok\"")));
                break;
            default:
                Matcher matcher = Pattern.compile("\\\\\"hb_cache_id\\\\\":\\[\\\\\"(.*?)\\\\\"\\]").matcher(str);
                ((org.prebid.mobile.c) this.b).a((!matcher.find() || matcher.groupCount() == 0) ? null : matcher.group(1));
                break;
        }
    }
}
