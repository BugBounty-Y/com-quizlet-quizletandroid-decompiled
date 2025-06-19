package com.quizlet.shared.usecase.studiableMetadata;

import androidx.camera.camera2.internal.c0;
import androidx.compose.ui.text.font.y;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.measurement.C3006i3;
import com.google.android.gms.internal.measurement.C3065u3;
import com.google.android.gms.internal.measurement.N2;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r;
import com.google.firebase.components.q;
import com.perimeterx.mobile_sdk.doctor_app.ui.m;
import com.quizlet.db.data.models.persisted.DBUser;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class a implements y, com.google.android.gms.dynamite.b, r, com.google.firebase.crashlytics.internal.stacktrace.a, com.google.firebase.components.d, com.google.zxing.datamatrix.encoder.b, com.perimeterx.mobile_sdk.doctor_app.state.d, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static JSONArray b(String str, JSONObject jSONObject) throws JSONException {
        JSONArray jSONArray = new JSONArray();
        if (jSONObject.has("purposeID")) {
            JSONObject jSONObject2 = new JSONObject();
            try {
                jSONObject2.put("id", jSONObject.getString("purposeID"));
                jSONObject2.put("TransactionType", str);
                jSONArray.put(jSONObject2);
                return jSONArray;
            } catch (JSONException e) {
                Z.p("Error on getting Google Ad purposeID. Error = ", e, "GoogleAdInfo", 6);
            }
        }
        return jSONArray;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x0109  */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void d(android.content.Context r19, org.json.JSONObject r20, boolean r21) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 359
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.a.d(android.content.Context, org.json.JSONObject, boolean):void");
    }

    public static com.quizlet.assembly.widgets.input.a h(int i) {
        com.quizlet.assembly.widgets.input.a aVar;
        com.quizlet.assembly.widgets.input.a[] aVarArrValues = com.quizlet.assembly.widgets.input.a.values();
        int length = aVarArrValues.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                aVar = null;
                break;
            }
            aVar = aVarArrValues[i2];
            if (aVar.a == i) {
                break;
            }
            i2++;
        }
        if (aVar != null) {
            return aVar;
        }
        throw new IllegalArgumentException("Invalid AssemblyInputLayout");
    }

    public static void n(com.google.zxing.datamatrix.encoder.c cVar, StringBuilder sb) {
        int iCharAt = (sb.charAt(1) * '(') + (sb.charAt(0) * 1600) + sb.charAt(2) + 1;
        cVar.c.append(new String(new char[]{(char) (iCharAt / 256), (char) (iCharAt % 256)}));
        sb.delete(0, 3);
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return com.perimeterx.mobile_sdk.doctor_app.state.a.b;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        DBUser p0 = (DBUser) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        return retrofit2.adapter.rxjava3.d.s(p0);
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new m();
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x004f  */
    @Override // com.google.firebase.crashlytics.internal.stacktrace.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.StackTraceElement[] e(java.lang.StackTraceElement[] r15) {
        /*
            r14 = this;
            java.util.HashMap r0 = new java.util.HashMap
            r0.<init>()
            int r1 = r15.length
            java.lang.StackTraceElement[] r1 = new java.lang.StackTraceElement[r1]
            r2 = 1
            r3 = 0
            r6 = r2
            r4 = r3
            r5 = r4
        Ld:
            int r7 = r15.length
            if (r4 >= r7) goto L61
            r7 = r15[r4]
            java.lang.Object r8 = r0.get(r7)
            java.lang.Integer r8 = (java.lang.Integer) r8
            if (r8 == 0) goto L4f
            int r9 = r8.intValue()
            int r10 = r4 - r9
            int r11 = r4 + r10
            int r12 = r15.length
            if (r11 <= r12) goto L26
            goto L4f
        L26:
            r11 = r3
        L27:
            if (r11 >= r10) goto L3b
            int r12 = r9 + r11
            r12 = r15[r12]
            int r13 = r4 + r11
            r13 = r15[r13]
            boolean r12 = r12.equals(r13)
            if (r12 != 0) goto L38
            goto L4f
        L38:
            int r11 = r11 + 1
            goto L27
        L3b:
            int r8 = r8.intValue()
            int r8 = r4 - r8
            r9 = 10
            if (r6 >= r9) goto L4b
            java.lang.System.arraycopy(r15, r4, r1, r5, r8)
            int r5 = r5 + r8
            int r6 = r6 + 1
        L4b:
            int r8 = r8 + (-1)
            int r8 = r8 + r4
            goto L57
        L4f:
            r6 = r15[r4]
            r1[r5] = r6
            int r5 = r5 + 1
            r6 = r2
            r8 = r4
        L57:
            java.lang.Integer r4 = java.lang.Integer.valueOf(r4)
            r0.put(r7, r4)
            int r4 = r8 + 1
            goto Ld
        L61:
            java.lang.StackTraceElement[] r0 = new java.lang.StackTraceElement[r5]
            java.lang.System.arraycopy(r1, r3, r0, r3, r5)
            int r1 = r15.length
            if (r5 >= r1) goto L6a
            return r0
        L6a:
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.a.e(java.lang.StackTraceElement[]):java.lang.StackTraceElement[]");
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.model.c(c0Var.c(q.a(com.google.mlkit.common.model.b.class)));
    }

    public int g(char c, StringBuilder sb) {
        if (c == ' ') {
            sb.append((char) 3);
            return 1;
        }
        if (c >= '0' && c <= '9') {
            sb.append((char) (c - ','));
            return 1;
        }
        if (c >= 'A' && c <= 'Z') {
            sb.append((char) (c - '3'));
            return 1;
        }
        if (c < ' ') {
            sb.append((char) 0);
            sb.append(c);
            return 2;
        }
        if (c >= '!' && c <= '/') {
            sb.append((char) 1);
            sb.append((char) (c - '!'));
            return 2;
        }
        if (c >= ':' && c <= '@') {
            sb.append((char) 1);
            sb.append((char) (c - '+'));
            return 2;
        }
        if (c >= '[' && c <= '_') {
            sb.append((char) 1);
            sb.append((char) (c - 'E'));
            return 2;
        }
        if (c < '`' || c > 127) {
            sb.append("\u0001\u001e");
            return g((char) (c - 128), sb) + 2;
        }
        sb.append((char) 2);
        sb.append((char) (c - '`'));
        return 2;
    }

    public int i() {
        return 1;
    }

    public void j(com.google.zxing.datamatrix.encoder.c cVar, StringBuilder sb) {
        int length = (sb.length() / 3) << 1;
        int length2 = sb.length() % 3;
        int length3 = cVar.c.length() + length;
        cVar.c(length3);
        int i = cVar.f.b - length3;
        if (length2 == 2) {
            sb.append((char) 0);
            while (sb.length() >= 3) {
                n(cVar, sb);
            }
            if (cVar.b()) {
                cVar.d((char) 254);
            }
        } else if (i == 1 && length2 == 1) {
            while (sb.length() >= 3) {
                n(cVar, sb);
            }
            if (cVar.b()) {
                cVar.d((char) 254);
            }
            cVar.d--;
        } else {
            if (length2 != 0) {
                throw new IllegalStateException("Unexpected case. Please report!");
            }
            while (sb.length() >= 3) {
                n(cVar, sb);
            }
            if (i > 0 || cVar.b()) {
                cVar.d((char) 254);
            }
        }
        cVar.e = 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001b A[PHI: r4
  0x001b: PHI (r4v2 int) = (r4v1 int), (r4v3 int) binds: [B:3:0x0014, B:5:0x0017] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.dynamite.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.bumptech.glide.load.engine.cache.f k(android.content.Context r3, java.lang.String r4, com.google.android.gms.dynamite.a r5) {
        /*
            r2 = this;
            com.bumptech.glide.load.engine.cache.f r0 = new com.bumptech.glide.load.engine.cache.f
            r0.<init>()
            int r1 = r5.e(r3, r4)
            r0.a = r1
            r1 = 1
            int r3 = r5.d(r3, r4, r1)
            r0.b = r3
            int r4 = r0.a
            if (r4 != 0) goto L1b
            r4 = 0
            if (r3 != 0) goto L1b
            r1 = r4
            goto L1f
        L1b:
            if (r3 < r4) goto L1e
            goto L1f
        L1e:
            r1 = -1
        L1f:
            r0.c = r1
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.studiableMetadata.a.k(android.content.Context, java.lang.String, com.google.android.gms.dynamite.a):com.bumptech.glide.load.engine.cache.f");
    }

    public p l(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarU = userProps.u();
        com.quizlet.quizletandroid.config.features.properties.d dVar = new com.quizlet.quizletandroid.config.features.properties.d(1);
        Boolean bool = Boolean.FALSE;
        return com.google.android.gms.dynamite.d.d(com.google.android.gms.dynamite.d.e(com.google.android.gms.dynamite.d.f(gVarU, userProps.o(dVar, bool))), userProps.q(), p.f(bool));
    }

    public boolean m(CharSequence charSequence) {
        return charSequence instanceof androidx.core.text.d;
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) N2.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.j0.b()).longValue());
            case 12:
                Boolean bool2 = (Boolean) C3065u3.a.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.I.b();
                l.getClass();
                return l;
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.S.b();
                l2.getClass();
                return l2;
            case 15:
                List list5 = AbstractC3893t.a;
                Boolean bool3 = (Boolean) C3006i3.a.b();
                bool3.getClass();
                return bool3;
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.V.b();
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.z.b()).longValue());
        }
    }

    public a(retrofit2.adapter.rxjava3.d dVar) {
        this.a = 28;
    }

    public void c(com.google.zxing.datamatrix.encoder.c cVar) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (!cVar.b()) {
                break;
            }
            char cA = cVar.a();
            cVar.d++;
            int iG = g(cA, sb);
            int length = cVar.c.length() + ((sb.length() / 3) << 1);
            cVar.c(length);
            int i = cVar.f.b - length;
            if (!cVar.b()) {
                StringBuilder sb2 = new StringBuilder();
                if (sb.length() % 3 == 2 && (i < 2 || i > 2)) {
                    int length2 = sb.length();
                    sb.delete(length2 - iG, length2);
                    cVar.d--;
                    iG = g(cVar.a(), sb2);
                    cVar.f = null;
                }
                while (sb.length() % 3 == 1 && ((iG <= 3 && i != 1) || iG > 3)) {
                    int length3 = sb.length();
                    sb.delete(length3 - iG, length3);
                    cVar.d--;
                    iG = g(cVar.a(), sb2);
                    cVar.f = null;
                }
            } else if (sb.length() % 3 == 0) {
                if (AbstractC3723t.f(cVar.a, cVar.d, i()) != i()) {
                    cVar.e = 0;
                    break;
                }
            }
        }
        j(cVar, sb);
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return new ArrayList();
    }
}
