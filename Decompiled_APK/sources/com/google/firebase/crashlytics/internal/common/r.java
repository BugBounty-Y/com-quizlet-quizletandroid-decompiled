package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import androidx.compose.ui.node.B;
import androidx.compose.ui.node.V;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.crashlytics.internal.model.T;
import com.google.firebase.crashlytics.internal.model.U;
import com.google.firebase.crashlytics.internal.model.X;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class r {
    public static final HashMap f;
    public static final String g;
    public final Context a;
    public final v b;
    public final V c;
    public final com.quizlet.data.repository.searchexplanations.c d;
    public final com.google.android.datatransport.cct.internal.s e;

    static {
        HashMap map = new HashMap();
        f = map;
        B.r(5, map, "armeabi", 6, "armeabi-v7a");
        B.r(9, map, "arm64-v8a", 0, "x86");
        map.put("x86_64", 1);
        Locale locale = Locale.US;
        g = "Crashlytics Android SDK/19.4.3";
    }

    public r(Context context, v vVar, V v, com.quizlet.data.repository.searchexplanations.c cVar, com.google.android.datatransport.cct.internal.s sVar) {
        this.a = context;
        this.b = vVar;
        this.c = v;
        this.d = cVar;
        this.e = sVar;
    }

    public static U c(com.quizlet.data.repository.classmembership.c cVar, int i) {
        String str = (String) cVar.b;
        int i2 = 0;
        StackTraceElement[] stackTraceElementArr = (StackTraceElement[]) cVar.c;
        if (stackTraceElementArr == null) {
            stackTraceElementArr = new StackTraceElement[0];
        }
        com.quizlet.data.repository.classmembership.c cVar2 = (com.quizlet.data.repository.classmembership.c) cVar.d;
        if (i >= 8) {
            for (com.quizlet.data.repository.classmembership.c cVar3 = cVar2; cVar3 != null; cVar3 = (com.quizlet.data.repository.classmembership.c) cVar3.d) {
                i2++;
            }
        }
        int i3 = i2;
        List listD = d(stackTraceElementArr, 4);
        if (listD == null) {
            throw new NullPointerException("Null frames");
        }
        byte b = (byte) (0 | 1);
        U uC = null;
        if (cVar2 != null && i3 == 0) {
            uC = c(cVar2, i + 1);
        }
        if (b == 1) {
            return new U(str, (String) cVar.a, listD, uC, i3);
        }
        StringBuilder sb = new StringBuilder();
        if ((b & 1) == 0) {
            sb.append(" overflowCount");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }

    public static List d(StackTraceElement[] stackTraceElementArr, int i) {
        ArrayList arrayList = new ArrayList();
        for (StackTraceElement stackTraceElement : stackTraceElementArr) {
            X x = new X();
            x.e = i;
            x.f = (byte) (x.f | 4);
            long lineNumber = 0;
            long jMax = stackTraceElement.isNativeMethod() ? Math.max(stackTraceElement.getLineNumber(), 0L) : 0L;
            String str = stackTraceElement.getClassName() + "." + stackTraceElement.getMethodName();
            String fileName = stackTraceElement.getFileName();
            if (!stackTraceElement.isNativeMethod() && stackTraceElement.getLineNumber() > 0) {
                lineNumber = stackTraceElement.getLineNumber();
            }
            x.a = jMax;
            byte b = (byte) (x.f | 1);
            x.f = b;
            if (str == null) {
                throw new NullPointerException("Null symbol");
            }
            x.b = str;
            x.c = fileName;
            x.d = lineNumber;
            x.f = (byte) (b | 2);
            arrayList.add(x.a());
        }
        return Collections.unmodifiableList(arrayList);
    }

    public static com.google.firebase.crashlytics.internal.model.V e() {
        byte b = (byte) 1;
        if (b == 1) {
            return new com.google.firebase.crashlytics.internal.model.V(0L, "0", "0");
        }
        StringBuilder sb = new StringBuilder();
        if (b == 0) {
            sb.append(" address");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }

    public final List a() {
        byte b = (byte) (((byte) (0 | 1)) | 2);
        V v = this.c;
        String str = (String) v.f;
        if (str == null) {
            throw new NullPointerException("Null name");
        }
        if (b == 3) {
            return Collections.singletonList(new T(0L, 0L, str, (String) v.c));
        }
        StringBuilder sb = new StringBuilder();
        if ((b & 1) == 0) {
            sb.append(" baseAddress");
        }
        if ((b & 2) == 0) {
            sb.append(" size");
        }
        throw new IllegalStateException(Z.i("Missing required properties:", sb));
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00a7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.firebase.crashlytics.internal.model.C3929c0 b(int r17) {
        /*
            Method dump skipped, instructions count: 241
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.r.b(int):com.google.firebase.crashlytics.internal.model.c0");
    }
}
