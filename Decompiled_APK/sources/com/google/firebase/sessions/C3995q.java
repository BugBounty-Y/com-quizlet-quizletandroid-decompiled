package com.google.firebase.sessions;

import android.app.Application;
import android.os.Build;
import android.os.Process;
import android.util.Log;
import androidx.datastore.core.CorruptionException;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3995q extends kotlin.jvm.internal.r implements Function1 {
    public static final C3995q b = new C3995q(1, 0);
    public static final C3995q c = new C3995q(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C3995q(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String strH;
        String strH2;
        switch (this.a) {
            case 0:
                CorruptionException ex = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(ex, "ex");
                StringBuilder sb = new StringBuilder("CorruptionException in settings DataStore in ");
                int i = Build.VERSION.SDK_INT;
                if (i > 33) {
                    strH = Process.myProcessName();
                    Intrinsics.checkNotNullExpressionValue(strH, "myProcessName()");
                } else if ((i < 28 || (strH = Application.getProcessName()) == null) && (strH = com.google.android.gms.common.util.c.h()) == null) {
                    strH = "";
                }
                sb.append(strH);
                sb.append('.');
                Log.w(FirebaseSessionsRegistrar.TAG, sb.toString(), ex);
                break;
            default:
                CorruptionException ex2 = (CorruptionException) obj;
                Intrinsics.checkNotNullParameter(ex2, "ex");
                StringBuilder sb2 = new StringBuilder("CorruptionException in sessions DataStore in ");
                int i2 = Build.VERSION.SDK_INT;
                if (i2 > 33) {
                    strH2 = Process.myProcessName();
                    Intrinsics.checkNotNullExpressionValue(strH2, "myProcessName()");
                } else if ((i2 < 28 || (strH2 = Application.getProcessName()) == null) && (strH2 = com.google.android.gms.common.util.c.h()) == null) {
                    strH2 = "";
                }
                sb2.append(strH2);
                sb2.append('.');
                Log.w(FirebaseSessionsRegistrar.TAG, sb2.toString(), ex2);
                break;
        }
        return Q6.a();
    }
}
