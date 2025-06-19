package com.google.android.gms.cloudmessaging;

import android.content.Context;
import android.graphics.Paint;
import android.graphics.PorterDuffXfermode;
import android.graphics.Shader;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Log;
import android.util.SparseIntArray;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.TextView;
import androidx.compose.ui.graphics.AbstractC0849i;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.a0;
import androidx.core.app.WindowOnFrameMetricsAvailableListenerC1022i;
import androidx.navigation.C1291m;
import com.android.billingclient.api.A;
import com.android.billingclient.api.p;
import com.android.billingclient.api.v;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.tasks.m;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes2.dex */
public final class k {
    public static k f;
    public static HandlerThread g;
    public static Handler h;
    public final /* synthetic */ int a;
    public int b;
    public Object c;
    public Object d;
    public Object e;

    public k(v vVar, int i, Consumer consumer, Runnable runnable) {
        this.a = 6;
        this.b = i;
        this.c = consumer;
        this.d = runnable;
        this.e = vVar;
    }

    public static int a(TextView textView, int i) {
        Typeface typeface;
        return (i != -1 || (typeface = textView.getTypeface()) == null) ? i : typeface.getStyle();
    }

    public static synchronized k p(Context context) {
        try {
            if (f == null) {
                f = new k(context, Executors.unconfigurableScheduledExecutorService(Executors.newScheduledThreadPool(1, new p("MessengerIpcClient", 2))));
            }
        } catch (Throwable th) {
            throw th;
        }
        return f;
    }

    public int b() {
        Paint.Cap strokeCap = ((Paint) this.c).getStrokeCap();
        int i = strokeCap == null ? -1 : AbstractC0849i.a[strokeCap.ordinal()];
        if (i == 1) {
            return 0;
        }
        if (i != 2) {
            return i != 3 ? 0 : 2;
        }
        return 1;
    }

    public int c() {
        Paint.Join strokeJoin = ((Paint) this.c).getStrokeJoin();
        int i = strokeJoin == null ? -1 : AbstractC0849i.b[strokeJoin.ordinal()];
        if (i == 1) {
            return 0;
        }
        if (i != 2) {
            return i != 3 ? 0 : 1;
        }
        return 2;
    }

    public void d(float f2) {
        ((Paint) this.c).setAlpha((int) Math.rint(f2 * 255.0f));
    }

    public void e(int i) {
        if (this.b == i) {
            return;
        }
        this.b = i;
        int i2 = Build.VERSION.SDK_INT;
        Paint paint = (Paint) this.c;
        if (i2 >= 29) {
            a0.a.a(paint, i);
        } else {
            paint.setXfermode(new PorterDuffXfermode(F.E(i)));
        }
    }

    public void f(long j) {
        ((Paint) this.c).setColor(F.A(j));
    }

    public void g(AbstractC0874w abstractC0874w) {
        this.e = abstractC0874w;
        ((Paint) this.c).setColorFilter(abstractC0874w != null ? abstractC0874w.a : null);
    }

    public void h(int i) {
        ((Paint) this.c).setFilterBitmap(!(i == 0));
    }

    public void i(Shader shader) {
        this.d = shader;
        ((Paint) this.c).setShader(shader);
    }

    public void j(int i) {
        ((Paint) this.c).setStrokeCap(i == 2 ? Paint.Cap.SQUARE : i == 1 ? Paint.Cap.ROUND : i == 0 ? Paint.Cap.BUTT : Paint.Cap.BUTT);
    }

    public void k(int i) {
        ((Paint) this.c).setStrokeJoin(i == 0 ? Paint.Join.MITER : i == 2 ? Paint.Join.BEVEL : i == 1 ? Paint.Join.ROUND : Paint.Join.MITER);
    }

    public void l(float f2) {
        ((Paint) this.c).setStrokeWidth(f2);
    }

    public void m(int i) {
        ((Paint) this.c).setStyle(i == 1 ? Paint.Style.STROKE : Paint.Style.FILL);
    }

    public void n(Throwable th) {
        boolean z = th instanceof TimeoutException;
        v vVar = (v) this.e;
        if (z) {
            vVar.F(114, 28, A.D);
            AbstractC3819n0.g("BillingClientTesting", "Asynchronous call to Billing Override Service timed out.", th);
        } else {
            vVar.F(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 28, A.D);
            AbstractC3819n0.g("BillingClientTesting", "An error occurred while retrieving billing override.", th);
        }
        ((Runnable) this.d).run();
    }

    public Looper o() {
        Looper looper;
        Object obj = this.e;
        synchronized (obj) {
            try {
                if (this.b != 0) {
                    u.i((HandlerThread) this.c, "Invalid state: handlerThread should already been initialized.");
                } else if (((HandlerThread) this.c) == null) {
                    com.google.android.gms.ads.internal.util.A.l("Starting the looper thread.");
                    HandlerThread handlerThread = new HandlerThread("LooperProvider");
                    this.c = handlerThread;
                    handlerThread.start();
                    this.d = new Ls(((HandlerThread) this.c).getLooper(), 0);
                    com.google.android.gms.ads.internal.util.A.l("Looper thread started.");
                } else {
                    com.google.android.gms.ads.internal.util.A.l("Resuming the looper thread");
                    obj.notifyAll();
                }
                this.b++;
                looper = ((HandlerThread) this.c).getLooper();
            } catch (Throwable th) {
                throw th;
            }
        }
        return looper;
    }

    public synchronized m q(j jVar) {
        try {
            if (Log.isLoggable("MessengerIpcClient", 3)) {
                "Queueing ".concat(jVar.toString());
            }
            if (!((i) this.e).d(jVar)) {
                i iVar = new i(this);
                this.e = iVar;
                iVar.d(jVar);
            }
        } catch (Throwable th) {
            throw th;
        }
        return jVar.b.a;
    }

    public String toString() {
        switch (this.a) {
            case 9:
                StringBuilder sb = new StringBuilder("FontProperty{fontName='");
                sb.append((String) this.c);
                sb.append("', fontSize='");
                sb.append((String) this.d);
                sb.append("', fontTextStyle='");
                sb.append(this.b);
                sb.append("', typefaceKey='");
                return android.support.v4.media.session.a.t(sb, (String) this.e, "'}");
            default:
                return super.toString();
        }
    }

    public k(Context context, ScheduledExecutorService scheduledExecutorService) {
        this.a = 0;
        this.e = new i(this);
        this.b = 1;
        this.d = scheduledExecutorService;
        this.c = context.getApplicationContext();
    }

    public k(InterfaceC2529qe interfaceC2529qe) throws com.google.android.gms.ads.internal.overlay.e {
        this.a = 7;
        this.d = interfaceC2529qe.getLayoutParams();
        ViewParent parent = interfaceC2529qe.getParent();
        this.c = interfaceC2529qe.J();
        if (parent != null && (parent instanceof ViewGroup)) {
            ViewGroup viewGroup = (ViewGroup) parent;
            this.e = viewGroup;
            this.b = viewGroup.indexOfChild(interfaceC2529qe.N());
            viewGroup.removeView(interfaceC2529qe.N());
            interfaceC2529qe.I0(true);
            return;
        }
        throw new com.google.android.gms.ads.internal.overlay.e("Could not get the parent of the WebView for an overlay.");
    }

    public k(com.airbnb.lottie.model.animatable.a aVar, com.airbnb.lottie.model.animatable.a aVar2, com.airbnb.lottie.model.animatable.a aVar3, int i) {
        this.a = 5;
        this.c = aVar;
        this.d = aVar2;
        this.e = aVar3;
        this.b = i;
    }

    public k(C1291m entry, int i) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(entry, "entry");
        this.c = entry.f;
        this.b = i;
        androidx.navigation.internal.c cVar = entry.h;
        this.d = cVar.a();
        V.c();
        Bundle outBundle = AbstractC3206m6.a((Pair[]) Arrays.copyOf(new Pair[0], 0));
        Intrinsics.checkNotNullParameter(outBundle, "source");
        this.e = outBundle;
        Intrinsics.checkNotNullParameter(outBundle, "outBundle");
        Intrinsics.checkNotNullParameter(outBundle, "outBundle");
        cVar.h.b(outBundle);
    }

    public k(Paint paint) {
        this.a = 1;
        this.c = paint;
        this.b = 3;
    }

    public k(Bundle source) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(source, "state");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter("nav-entry-state:id", "key");
        String string = source.getString("nav-entry-state:id");
        if (string != null) {
            this.c = string;
            Intrinsics.checkNotNullParameter(source, "source");
            this.b = AbstractC3335e2.f(source, "nav-entry-state:destination-id");
            Intrinsics.checkNotNullParameter(source, "source");
            this.d = AbstractC3335e2.h(source, "nav-entry-state:args");
            Intrinsics.checkNotNullParameter(source, "source");
            this.e = AbstractC3335e2.h(source, "nav-entry-state:saved-state");
            return;
        }
        AbstractC3339f2.h("nav-entry-state:id");
        throw null;
    }

    public k(LinkedHashSet neverCorrect, LinkedHashSet correctOnceAndNotFinished, LinkedHashSet finished, int i) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(neverCorrect, "neverCorrect");
        Intrinsics.checkNotNullParameter(correctOnceAndNotFinished, "correctOnceAndNotFinished");
        Intrinsics.checkNotNullParameter(finished, "finished");
        this.c = neverCorrect;
        this.d = correctOnceAndNotFinished;
        this.e = finished;
        this.b = i;
    }

    public k(int i, CoroutineContext coroutineContext, kotlinx.coroutines.channels.a aVar, InterfaceC4992i interfaceC4992i) {
        this.a = 10;
        this.c = interfaceC4992i;
        this.b = i;
        this.d = aVar;
        this.e = coroutineContext;
    }

    public k(int i) {
        this.a = i;
        switch (i) {
            case 8:
                this.c = null;
                this.d = null;
                this.b = 0;
                this.e = new Object();
                break;
            case 9:
                this.b = -1;
                break;
            default:
                this.c = new SparseIntArray[9];
                this.d = new ArrayList();
                this.e = new WindowOnFrameMetricsAvailableListenerC1022i(this);
                this.b = 1;
                break;
        }
    }
}
