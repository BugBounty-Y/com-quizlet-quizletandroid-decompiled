package com.quizlet.features.setpage.logging;

import androidx.compose.foundation.lazy.grid.C0427b;
import androidx.compose.foundation.lazy.grid.v;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.quizlet.eventlogger.model.AndroidEventLog;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;

    public /* synthetic */ a(int i, int i2) {
        this.a = i2;
        this.b = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("set_page_term_list_depth_on_leave");
                logUserActionAndroidEvent.setDepth(Integer.valueOf(this.b));
                break;
            case 1:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.setDepth(Integer.valueOf(this.b));
                break;
            case 2:
                v item = (v) obj;
                Intrinsics.checkNotNullParameter(item, "$this$item");
                break;
            case 3:
                v item2 = (v) obj;
                Intrinsics.checkNotNullParameter(item2, "$this$item");
                break;
            case 4:
                v item3 = (v) obj;
                Intrinsics.checkNotNullParameter(item3, "$this$item");
                break;
            case 5:
                v item4 = (v) obj;
                Intrinsics.checkNotNullParameter(item4, "$this$item");
                break;
            default:
                v item5 = (v) obj;
                Intrinsics.checkNotNullParameter(item5, "$this$item");
                break;
        }
        return new C0427b(AbstractC3173j0.d(this.b));
    }
}
