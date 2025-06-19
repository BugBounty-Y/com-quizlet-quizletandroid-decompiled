package com.google.mlkit.vision.camera;

import android.os.SystemClock;
import android.util.Size;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.c0;
import androidx.camera.core.C0192o;
import androidx.compose.foundation.gestures.l1;
import androidx.lifecycle.B;
import androidx.lifecycle.C;
import androidx.lifecycle.J;
import androidx.lifecycle.L;
import com.amazon.device.ads.DtbConstants;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.internal.C1658h;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.mlkit_vision_camera.C3393t1;
import com.google.android.gms.internal.mlkit_vision_camera.EnumC3385r1;
import com.google.android.gms.internal.mlkit_vision_camera.EnumC3389s1;
import com.google.android.gms.internal.mlkit_vision_camera.f3;
import com.google.android.gms.tasks.m;
import com.google.firebase.messaging.p;
import com.google.mlkit.common.sdkinternal.k;
import com.google.mlkit.vision.barcode.internal.c;
import com.quizlet.data.repository.widget.b;
import io.ktor.client.plugins.api.d;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public final class a implements J {
    public static final b l = new b("CameraXSource", "");
    public final com.google.mlkit.vision.camera.internal.a a;
    public final p b;
    public final C0192o c;
    public final com.quizlet.data.interactor.school.b d;
    public final f3 e;
    public final C0122z f;
    public final androidx.camera.core.impl.utils.futures.b g;
    public final L h;
    public Size i;
    public final WeakReference j;
    public final com.quizlet.data.repository.activitycenter.b k;

    /* JADX WARN: Can't wrap try/catch for region: R(17:0|2|8|15|16|(0)(0)|20|(0)(0)|24|66|25|61|26|27|31|bb|(1:(0))) */
    /* JADX WARN: Removed duplicated region for block: B:18:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x003c  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00bc A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public a(androidx.appcompat.widget.C0122z r10, androidx.camera.view.PreviewView r11) {
        /*
            Method dump skipped, instructions count: 330
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.vision.camera.a.<init>(androidx.appcompat.widget.z, androidx.camera.view.PreviewView):void");
    }

    public final void a() {
        c();
        this.a.b.set(true);
        L l2 = this.h;
        if (l2.d != B.c) {
            return;
        }
        l2.g(B.a);
        l.g("close");
        com.quizlet.data.interactor.school.b bVar = this.d;
        bVar.getClass();
        try {
            ((c) bVar.b).close();
        } catch (IOException unused) {
        }
        e(EnumC3389s1.EVENT_TYPE_CLOSE);
    }

    public final void b() {
        l.g("start cameraXSource without preview view.");
        L l2 = this.h;
        B b = l2.d;
        B b2 = B.d;
        if (b == b2) {
            return;
        }
        if (b != B.c) {
            throw new IllegalStateException("Camera has not been created or has already been closed.");
        }
        l2.g(b2);
        if (this.j != null) {
            e(EnumC3389s1.EVENT_TYPE_START_WITH_PREVIEW);
        } else {
            e(EnumC3389s1.EVENT_TYPE_START);
        }
    }

    public final void c() {
        L l2 = this.h;
        B b = l2.d;
        B b2 = B.c;
        if (b == b2) {
            l.g("Already in the CREATE state");
        } else {
            if (b != B.d) {
                return;
            }
            l2.g(b2);
            e(EnumC3389s1.EVENT_TYPE_STOP);
        }
    }

    public final void d(int i) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        com.quizlet.data.repository.activitycenter.b bVar = this.k;
        int i2 = i - 1;
        synchronized (bVar) {
            long jElapsedRealtime = SystemClock.elapsedRealtime();
            if (((AtomicLong) bVar.c).get() != -1 && jElapsedRealtime - ((AtomicLong) bVar.c).get() <= TimeUnit.MINUTES.toMillis(30L)) {
                return;
            }
            ((com.google.android.gms.common.internal.service.b) bVar.b).d(new TelemetryData(0, Arrays.asList(new MethodInvocation(24321, i2, 0, jCurrentTimeMillis, jCurrentTimeMillis, null, null, 0, -1)))).o(new l1(bVar, jElapsedRealtime, 11));
        }
    }

    public final void e(EnumC3389s1 enumC3389s1) {
        d dVar = new d(6);
        c0 c0Var = new c0(10, false);
        this.f.getClass();
        c0Var.e = Integer.valueOf(DtbConstants.DEFAULT_PLAYER_HEIGHT);
        c0Var.d = 360;
        Size size = this.i;
        c0Var.g = Integer.valueOf((size == null ? 0 : size.getWidth()) & SubsamplingScaleImageView.TILE_SIZE_AUTO);
        Size size2 = this.i;
        c0Var.f = Integer.valueOf((size2 != null ? size2.getHeight() : 0) & SubsamplingScaleImageView.TILE_SIZE_AUTO);
        c0Var.b = EnumC3385r1.SOURCE_CAMERAX;
        c0Var.c = enumC3389s1;
        dVar.d = new C3393t1(c0Var);
        com.quizlet.data.repository.explanations.myexplanations.a aVar = new com.quizlet.data.repository.explanations.myexplanations.a(dVar);
        f3 f3Var = this.e;
        m mVar = f3Var.e;
        k.a.execute(new androidx.core.provider.k(f3Var, aVar, mVar.l() ? (String) mVar.h() : C1658h.c.a(f3Var.g)));
    }

    @Override // androidx.lifecycle.J
    public final C getLifecycle() {
        return this.h;
    }
}
