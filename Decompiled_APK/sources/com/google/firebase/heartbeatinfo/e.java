package com.google.firebase.heartbeatinfo;

import android.content.Context;
import android.hardware.camera2.CameraCharacteristics;
import android.view.GestureDetector;
import android.view.ViewConfiguration;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.camera2.internal.C0137n;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.compat.k;
import androidx.camera.camera2.internal.s0;
import androidx.camera.core.impl.i0;
import com.bumptech.glide.manager.m;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.P3;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.V3;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.InterfaceC3862d;
import com.google.android.gms.measurement.internal.r;
import com.google.gson.internal.n;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements androidx.lifecycle.viewmodel.b, m, com.google.android.gms.ads.mediation.customevent.b, InterfaceC3862d, r, n, com.google.firebase.components.d {
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    public static PracticeTestConfigurationData a(LinkedHashMap questionCounts) {
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        Integer num = (Integer) questionCounts.get(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER);
        int iIntValue = num != null ? num.intValue() : 0;
        if (iIntValue > 20) {
            iIntValue = 20;
        }
        return new PracticeTestConfigurationData(iIntValue, true, false);
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new TreeMap();
    }

    public io.reactivex.rxjava3.internal.operators.single.g b(androidx.work.impl.model.c userProps, Object obj) {
        com.quizlet.infra.legacysyncengine.features.properties.d contentProps = (com.quizlet.infra.legacysyncengine.features.properties.d) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.h);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarG2 = contentProps.a().g(com.quizlet.infra.legacysyncengine.features.properties.c.g);
        Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
        return com.google.android.gms.dynamite.d.b(com.google.android.gms.dynamite.d.f(gVarG, gVarG2), com.google.android.gms.dynamite.d.e(userProps.u()));
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.model.b(c0Var.b(com.google.mlkit.common.internal.model.a.class));
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3862d
    public String g(String str, String str2) {
        return null;
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 11:
                List list = AbstractC3893t.a;
                W3.b.get();
                Boolean bool = (Boolean) Y3.h.b();
                bool.getClass();
                return bool;
            case 12:
                Boolean bool2 = (Boolean) P3.a.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list2 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.n0.b()).longValue());
            case 14:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.O.b();
                l.getClass();
                return l;
            case 15:
                Boolean bool3 = (Boolean) V3.a.b();
                bool3.getClass();
                return bool3;
            case 16:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.q.b()).longValue());
            default:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.j.b();
        }
    }

    public e(Context context, s0 listener) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(listener, "listener");
        ViewConfiguration.get(context).getScaledTouchSlop();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(listener, "listener");
        new GestureDetector(context, new androidx.camera.view.impl.a(this, 0));
    }

    public e(com.quizlet.time.b timeUtils) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(timeUtils, "timeUtils");
    }

    public e(C0137n c0137n, k kVar, i0 i0Var, androidx.camera.core.impl.utils.executor.k kVar2, androidx.camera.core.impl.utils.executor.e eVar) {
        this.a = 1;
        Integer num = (Integer) kVar.a(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
        if (num != null) {
            num.intValue();
        }
        new com.google.mlkit.common.sdkinternal.model.a(i0Var);
        com.google.android.gms.common.wrappers.a.e(new C0132i(kVar, 1));
    }
}
