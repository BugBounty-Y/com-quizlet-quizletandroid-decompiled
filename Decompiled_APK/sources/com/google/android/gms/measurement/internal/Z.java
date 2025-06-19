package com.google.android.gms.measurement.internal;

import android.content.SharedPreferences;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0814p;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.firebase.perf.util.Timer;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes2.dex */
public abstract /* synthetic */ class Z {
    public static /* synthetic */ int a(int i) {
        int i2 = 1;
        if (i != 1) {
            i2 = 2;
            if (i != 2) {
                i2 = 3;
                if (i != 3) {
                    if (i == 4) {
                        return 4;
                    }
                    throw null;
                }
            }
        }
        return i2;
    }

    public static /* synthetic */ long b(int i) {
        if (i == 1) {
            return 1099511627776L;
        }
        if (i == 2) {
            return 1073741824L;
        }
        if (i == 3) {
            return 1048576L;
        }
        if (i == 4) {
            return 1024L;
        }
        if (i == 5) {
            return 1L;
        }
        throw null;
    }

    public static View c(ViewGroup viewGroup, int i, ViewGroup viewGroup2, boolean z) {
        return LayoutInflater.from(viewGroup.getContext()).inflate(i, viewGroup2, z);
    }

    public static androidx.compose.ui.graphics.painter.b d(int i, C0814p c0814p, int i2, boolean z, boolean z2) {
        androidx.compose.ui.graphics.painter.b bVarA = Z4.a(i, c0814p, i2);
        c0814p.p(z);
        c0814p.p(z2);
        return bVarA;
    }

    public static Y0 e(Y y) {
        Y0 y0R = y.r();
        y0R.S();
        y0R.Q();
        return y0R;
    }

    public static io.reactivex.rxjava3.subjects.r f(String str) {
        io.reactivex.rxjava3.subjects.r rVar = new io.reactivex.rxjava3.subjects.r();
        Intrinsics.checkNotNullExpressionValue(rVar, str);
        return rVar;
    }

    public static Object g(int i, C0814p c0814p, boolean z) {
        c0814p.p(z);
        c0814p.X(i);
        return c0814p.I();
    }

    public static String h(C0814p c0814p, int i, int i2, C0814p c0814p2, boolean z) {
        c0814p.X(i);
        String strD = AbstractC3106b5.d(c0814p2, i2);
        c0814p.p(z);
        return strD;
    }

    public static String i(String str, StringBuilder sb) {
        return str + ((Object) sb);
    }

    public static NoWhenBranchMatchedException j(int i, C0814p c0814p, boolean z) {
        c0814p.X(i);
        c0814p.p(z);
        return new NoWhenBranchMatchedException();
    }

    public static void k(long j, com.squareup.moshi.l lVar, com.squareup.moshi.w wVar, String str) {
        lVar.g(wVar, Long.valueOf(j));
        wVar.l(str);
    }

    public static void l(r1 r1Var) {
        r1Var.i().S();
        r1Var.k();
    }

    public static void m(Timer timer, com.google.firebase.perf.metrics.d dVar, com.google.firebase.perf.metrics.d dVar2) {
        dVar.j(timer.a());
        com.google.firebase.perf.network.g.c(dVar2);
    }

    public static void n(String str, Exception exc, String str2, int i) {
        com.google.android.gms.internal.mlkit_vision_document_scanner.O.a(exc, new StringBuilder(str), str2, i);
    }

    public static void o(String str, JSONException jSONException, String str2) {
        OTLogger.c(str2, 6, str + jSONException.toString());
    }

    public static void p(String str, JSONException jSONException, String str2, int i) {
        com.google.android.gms.internal.mlkit_vision_document_scanner.T.d(jSONException, new StringBuilder(str), str2, i);
    }

    public static void q(boolean z, com.squareup.moshi.l lVar, com.squareup.moshi.w wVar, String str) {
        lVar.g(wVar, Boolean.valueOf(z));
        wVar.l(str);
    }

    public static boolean r(Boolean bool, SharedPreferences sharedPreferences, String str) {
        return AbstractC3605e0.a(sharedPreferences.getString(str, bool.toString()));
    }

    public static /* synthetic */ String s(int i) {
        switch (i) {
            case 1:
                return "BEGIN_ARRAY";
            case 2:
                return "END_ARRAY";
            case 3:
                return "BEGIN_OBJECT";
            case 4:
                return "END_OBJECT";
            case 5:
                return "NAME";
            case 6:
                return "STRING";
            case 7:
                return "NUMBER";
            case 8:
                return "BOOLEAN";
            case 9:
                return "NULL";
            case 10:
                return "END_DOCUMENT";
            default:
                return "null";
        }
    }

    public static /* synthetic */ String t(int i) {
        switch (i) {
            case 1:
                return "AZTEC";
            case 2:
                return "CODABAR";
            case 3:
                return "CODE_39";
            case 4:
                return "CODE_93";
            case 5:
                return "CODE_128";
            case 6:
                return "DATA_MATRIX";
            case 7:
                return "EAN_8";
            case 8:
                return "EAN_13";
            case 9:
                return "ITF";
            case 10:
                return "MAXICODE";
            case 11:
                return "PDF_417";
            case 12:
                return "QR_CODE";
            case 13:
                return "RSS_14";
            case 14:
                return "RSS_EXPANDED";
            case 15:
                return "UPC_A";
            case 16:
                return "UPC_E";
            case 17:
                return "UPC_EAN_EXTENSION";
            default:
                return "null";
        }
    }
}
