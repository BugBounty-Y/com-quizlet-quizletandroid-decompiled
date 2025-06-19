package com.quizlet.shared.usecase.folderstudymaterials;

import androidx.camera.camera2.internal.c0;
import androidx.compose.ui.graphics.L;
import androidx.compose.ui.graphics.N;
import androidx.compose.ui.graphics.V;
import androidx.compose.ui.unit.k;
import androidx.fragment.app.Fragment;
import com.airbnb.lottie.parser.l;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.C2976c3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.K2;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.mlkit_vision_barcode.R4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.quizlet.data.model.D1;
import com.quizlet.data.model.E1;
import com.quizlet.data.model.p2;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class d implements h, V, androidx.profileinstaller.c, com.facebook.e, com.google.android.gms.dynamite.b, r, com.google.firebase.crashlytics.internal.settings.c, com.google.firebase.components.d, com.google.zxing.datamatrix.encoder.b, com.perimeterx.mobile_sdk.doctor_app.state.d, com.quizlet.local.ormlite.util.c {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    public static D1 l(DBSelectedTerm local) {
        Intrinsics.checkNotNullParameter(local, "local");
        if (local.getDeleted()) {
            return new p2(local.getTermId(), local.getPersonId(), local.getDeleted());
        }
        return new E1(local.getTermId(), local.getPersonId(), local.getSource(), local.getSetId());
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return com.perimeterx.mobile_sdk.doctor_app.state.a.a;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return com.perimeterx.mobile_sdk.doctor_app.state.a.a;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new com.perimeterx.mobile_sdk.doctor_app.ui.h();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return new ArrayList();
    }

    @Override // androidx.compose.ui.graphics.V
    public N e(long j, k kVar, androidx.compose.ui.unit.b bVar) {
        return new L(R4.a(0L, j));
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.sdkinternal.model.a(0);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return l((DBSelectedTerm) obj);
    }

    @Override // com.facebook.e
    public String i() {
        return "fb_extend_sso_token";
    }

    @Override // com.facebook.e
    public String j() {
        return "oauth/access_token";
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
            goto L1e
        L1b:
            if (r4 < r3) goto L1e
            r1 = -1
        L1e:
            r0.c = r1
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.d.k(android.content.Context, java.lang.String, com.google.android.gms.dynamite.a):com.bumptech.glide.load.engine.cache.f");
    }

    /* JADX WARN: Code restructure failed: missing block: B:60:0x01ba, code lost:
    
        if (r0.d.l(r1, r10) == r5) goto L61;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:25:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /* JADX WARN: Type inference failed for: r10v17, types: [okio.n] */
    /* JADX WARN: Type inference failed for: r14v8, types: [com.mayakapps.kache.y] */
    /* JADX WARN: Type inference failed for: r15v7, types: [kotlinx.coroutines.C] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:44:0x0115 -> B:53:0x0160). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:48:0x0138 -> B:49:0x0147). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(okio.t r20, okio.x r21, long r22, com.mayakapps.kache.x r24, kotlinx.coroutines.internal.d r25, int r26, com.mayakapps.kache.K r27, kotlin.coroutines.jvm.internal.c r28) {
        /*
            Method dump skipped, instructions count: 455
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.folderstudymaterials.d.m(okio.t, okio.x, long, com.mayakapps.kache.x, kotlinx.coroutines.internal.d, int, com.mayakapps.kache.K, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public String toString() {
        switch (this.a) {
            case 2:
                return "RectangleShape";
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) C2976c3.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool2 = (Boolean) G3.a.b();
                bool2.getClass();
                return bool2;
            case 12:
                Boolean bool3 = (Boolean) K2.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.G.b();
                l.getClass();
                return l;
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l2 = (Long) Q2.x.b();
                l2.getClass();
                return l2;
            case 15:
                List list5 = AbstractC3893t.a;
                B3.b.get();
                return (String) D3.f.b();
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.n.b()).longValue());
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                Boolean bool4 = (Boolean) Q2.c.b();
                bool4.getClass();
                return bool4;
        }
    }

    @Override // com.google.firebase.crashlytics.internal.settings.c
    public com.google.firebase.crashlytics.internal.settings.a a(com.onetrust.otpublishers.headless.Internal.Helper.h hVar, JSONObject jSONObject) throws JSONException {
        jSONObject.optInt("settings_version", 0);
        int iOptInt = jSONObject.optInt("cache_duration", 3600);
        double dOptDouble = jSONObject.optDouble("on_demand_upload_rate_per_minute", 10.0d);
        double dOptDouble2 = jSONObject.optDouble("on_demand_backoff_base", 1.2d);
        int iOptInt2 = jSONObject.optInt("on_demand_backoff_step_duration_seconds", 60);
        l lVar = jSONObject.has("session") ? new l(jSONObject.getJSONObject("session").optInt("max_custom_exception_events", 8), 11) : new l(new JSONObject().optInt("max_custom_exception_events", 8), 11);
        JSONObject jSONObject2 = jSONObject.getJSONObject("features");
        return new com.google.firebase.crashlytics.internal.settings.a(jSONObject.has("expires_at") ? jSONObject.optLong("expires_at") : (iOptInt * 1000) + System.currentTimeMillis(), lVar, new androidx.camera.camera2.internal.compat.workaround.c(jSONObject2.optBoolean("collect_reports", true), jSONObject2.optBoolean("collect_anrs", false), jSONObject2.optBoolean("collect_build_ids", false)), dOptDouble, dOptDouble2, iOptInt2);
    }

    @Override // androidx.profileinstaller.c
    public void b(int i, Serializable serializable) {
    }

    @Override // com.google.zxing.datamatrix.encoder.b
    public void c(com.google.zxing.datamatrix.encoder.c cVar) {
        int i;
        int i2 = cVar.d;
        String str = cVar.a;
        int length = str.length();
        if (i2 < length) {
            char cCharAt = str.charAt(i2);
            i = 0;
            while (AbstractC3723t.c(cCharAt) && i2 < length) {
                i++;
                i2++;
                if (i2 < length) {
                    cCharAt = str.charAt(i2);
                }
            }
        } else {
            i = 0;
        }
        if (i >= 2) {
            char cCharAt2 = str.charAt(cVar.d);
            char cCharAt3 = str.charAt(cVar.d + 1);
            if (AbstractC3723t.c(cCharAt2) && AbstractC3723t.c(cCharAt3)) {
                cVar.d((char) ((cCharAt3 - '0') + ((cCharAt2 - '0') * 10) + 130));
                cVar.d += 2;
                return;
            } else {
                throw new IllegalArgumentException("not digits: " + cCharAt2 + cCharAt3);
            }
        }
        char cA = cVar.a();
        int iF = AbstractC3723t.f(str, cVar.d, 0);
        if (iF == 0) {
            if (!AbstractC3723t.d(cA)) {
                cVar.d((char) (cA + 1));
                cVar.d++;
                return;
            } else {
                cVar.d((char) 235);
                cVar.d((char) (cA - 127));
                cVar.d++;
                return;
            }
        }
        if (iF == 1) {
            cVar.d((char) 230);
            cVar.e = 1;
            return;
        }
        if (iF == 2) {
            cVar.d((char) 239);
            cVar.e = 2;
            return;
        }
        if (iF == 3) {
            cVar.d((char) 238);
            cVar.e = 3;
        } else if (iF == 4) {
            cVar.d((char) 240);
            cVar.e = 4;
        } else {
            if (iF != 5) {
                throw new IllegalStateException("Illegal mode: ".concat(String.valueOf(iF)));
            }
            cVar.d((char) 231);
            cVar.e = 5;
        }
    }
}
