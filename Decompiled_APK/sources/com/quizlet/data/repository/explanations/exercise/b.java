package com.quizlet.data.repository.explanations.exercise;

import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.util.Base64;
import android.view.MotionEvent;
import androidx.browser.customtabs.k;
import androidx.camera.core.impl.C0186z;
import androidx.datastore.core.P;
import androidx.work.impl.model.c;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BA;
import com.google.android.gms.internal.ads.C1669Be;
import com.google.android.gms.internal.ads.C1739Nc;
import com.google.android.gms.internal.ads.C1843ak;
import com.google.android.gms.internal.ads.C2107gm;
import com.google.android.gms.internal.ads.C2217j9;
import com.google.android.gms.internal.ads.C2253k2;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2743ve;
import com.google.android.gms.internal.ads.C2770w4;
import com.google.android.gms.internal.ads.C2813x4;
import com.google.android.gms.internal.ads.C2830xf;
import com.google.android.gms.internal.ads.C2905zA;
import com.google.android.gms.internal.ads.Gg;
import com.google.android.gms.internal.ads.InterfaceC1818a2;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.X1;
import com.google.android.gms.internal.ads.Xp;
import com.google.android.gms.internal.ads.Yo;
import com.google.android.gms.internal.ads.zzfps;
import com.quizlet.ads.d;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.Z;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.zip.Inflater;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class b implements InterfaceC1818a2, Pv, h {
    public Object a;
    public final Object b;
    public Object c;
    public Object d;

    public b(C1843ak c1843ak, Vp vp, Xp xp, C2830xf c2830xf) {
        this.a = vp;
        this.b = xp;
        this.c = c2830xf;
        this.d = c1843ak;
    }

    public static String m(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        C2770w4 c2770w4W = C2813x4.w();
        c2770w4W.e();
        C2813x4.z((C2813x4) c2770w4W.b, 5);
        C2905zA c2905zAW = BA.w(0, bArr, bArr.length);
        c2770w4W.e();
        C2813x4.x((C2813x4) c2770w4W.b, c2905zAW);
        return Base64.encodeToString(((C2813x4) c2770w4W.c()).d(), 11);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public void a(byte[] bArr, int i, int i2, C0186z c0186z) {
        int i3;
        Gg gg;
        int i4;
        int i5;
        Kn kn;
        int i6;
        int i7;
        int iB;
        int i8 = 128;
        Kn kn2 = (Kn) this.a;
        kn2.h(i + i2, bArr);
        kn2.j(i);
        if (((Inflater) this.d) == null) {
            this.d = new Inflater();
        }
        Inflater inflater = (Inflater) this.d;
        Kn kn3 = (Kn) this.b;
        if (Yo.f(kn2, kn3, inflater)) {
            kn2.h(kn3.c, kn3.a);
        }
        C2253k2 c2253k2 = (C2253k2) this.c;
        int i9 = 0;
        c2253k2.d = 0;
        c2253k2.e = 0;
        c2253k2.f = 0;
        c2253k2.g = 0;
        c2253k2.h = 0;
        c2253k2.i = 0;
        Kn kn4 = c2253k2.a;
        kn4.g(0);
        c2253k2.c = false;
        ArrayList arrayList = new ArrayList();
        while (kn2.s() >= 3) {
            int i10 = kn2.c;
            int iZ = kn2.z();
            int iD = kn2.D();
            int i11 = kn2.b + iD;
            if (i11 > i10) {
                kn2.j(i10);
                i3 = i8;
                i4 = i9;
                gg = null;
            } else {
                int[] iArr = c2253k2.b;
                if (iZ != i8) {
                    switch (iZ) {
                        case 20:
                            if (iD % 5 != 2) {
                                kn = kn2;
                            } else {
                                kn2.k(2);
                                Arrays.fill(iArr, i9);
                                int i12 = iD / 5;
                                int i13 = i9;
                                while (i13 < i12) {
                                    int iZ2 = kn2.z();
                                    int iZ3 = kn2.z();
                                    int iZ4 = kn2.z();
                                    double d = iZ3;
                                    int iZ5 = kn2.z() - 128;
                                    int iZ6 = kn2.z() << 24;
                                    String str = Yo.a;
                                    double d2 = iZ4 - 128;
                                    double d3 = iZ5;
                                    iArr[iZ2] = (Math.max(0, Math.min((int) ((d - (0.34414d * d3)) - (d2 * 0.71414d)), 255)) << 8) | iZ6 | (Math.max(0, Math.min((int) ((1.402d * d2) + d), 255)) << 16) | Math.max(0, Math.min((int) ((d3 * 1.772d) + d), 255));
                                    i13++;
                                    kn2 = kn2;
                                }
                                kn = kn2;
                                c2253k2.c = true;
                            }
                            kn2 = kn;
                            i3 = 128;
                            gg = null;
                            i4 = 0;
                            break;
                        case 21:
                            if (iD >= 4) {
                                kn2.k(3);
                                int i14 = iD - 4;
                                if ((kn2.z() & i8) == 0) {
                                    i6 = kn4.b;
                                    i7 = kn4.c;
                                    if (i6 < i7 && i14 > 0) {
                                        int iMin = Math.min(i14, i7 - i6);
                                        kn2.f(i6, kn4.a, iMin);
                                        kn4.j(i6 + iMin);
                                    }
                                } else if (i14 >= 7 && (iB = kn2.B()) >= 4) {
                                    c2253k2.h = kn2.D();
                                    c2253k2.i = kn2.D();
                                    kn4.g(iB - 4);
                                    i14 = iD - 11;
                                    i6 = kn4.b;
                                    i7 = kn4.c;
                                    if (i6 < i7) {
                                        int iMin2 = Math.min(i14, i7 - i6);
                                        kn2.f(i6, kn4.a, iMin2);
                                        kn4.j(i6 + iMin2);
                                    }
                                }
                            }
                            i3 = i8;
                            i4 = i9;
                            gg = null;
                            break;
                        case EventType.WINDOW_STATE /* 22 */:
                            if (iD >= 19) {
                                c2253k2.d = kn2.D();
                                c2253k2.e = kn2.D();
                                kn2.k(11);
                                c2253k2.f = kn2.D();
                                c2253k2.g = kn2.D();
                            }
                            i3 = i8;
                            i4 = i9;
                            gg = null;
                            break;
                        default:
                            i3 = i8;
                            i4 = i9;
                            gg = null;
                            break;
                    }
                } else {
                    Kn kn5 = kn2;
                    if (c2253k2.d == 0 || c2253k2.e == 0 || c2253k2.h == 0 || c2253k2.i == 0 || (i5 = kn4.c) == 0 || kn4.b != i5 || !c2253k2.c) {
                        i3 = 128;
                        gg = null;
                    } else {
                        kn4.j(0);
                        int i15 = c2253k2.h * c2253k2.i;
                        int[] iArr2 = new int[i15];
                        int i16 = 0;
                        while (i16 < i15) {
                            int iZ7 = kn4.z();
                            if (iZ7 != 0) {
                                iArr2[i16] = iArr[iZ7];
                                i16++;
                            } else {
                                int iZ8 = kn4.z();
                                if (iZ8 != 0) {
                                    int iZ9 = iZ8 & 63;
                                    if ((iZ8 & 64) != 0) {
                                        iZ9 = (iZ9 << 8) | kn4.z();
                                    }
                                    int i17 = (iZ8 & 128) == 0 ? iArr[0] : iArr[kn4.z()];
                                    int i18 = i16 + iZ9;
                                    Arrays.fill(iArr2, i16, i18, i17);
                                    i16 = i18;
                                }
                            }
                        }
                        i3 = 128;
                        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(iArr2, c2253k2.h, c2253k2.i, Bitmap.Config.ARGB_8888);
                        float f = c2253k2.f;
                        float f2 = c2253k2.d;
                        float f3 = f / f2;
                        float f4 = c2253k2.g;
                        float f5 = c2253k2.e;
                        gg = new Gg(null, null, null, bitmapCreateBitmap, f4 / f5, 0, 0, f3, 0, Integer.MIN_VALUE, -3.4028235E38f, c2253k2.h / f2, c2253k2.i / f5, Integer.MIN_VALUE, DefinitionKt.NO_Float_VALUE);
                    }
                    i4 = 0;
                    c2253k2.d = 0;
                    c2253k2.e = 0;
                    c2253k2.f = 0;
                    c2253k2.g = 0;
                    c2253k2.h = 0;
                    c2253k2.i = 0;
                    kn4.g(0);
                    c2253k2.c = false;
                    kn2 = kn5;
                }
                kn2.j(i11);
            }
            if (gg != null) {
                arrayList.add(gg);
            }
            i8 = i3;
            i9 = i4;
        }
        c0186z.mo10b(new X1(arrayList, -9223372036854775807L, -9223372036854775807L));
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        p c4885d;
        int i = 2;
        int i2 = 0;
        Long userId = (Long) obj;
        Intrinsics.checkNotNullParameter(userId, "userId");
        com.quizlet.quizletandroid.ui.promo.rateus.b bVar = new com.quizlet.quizletandroid.ui.promo.rateus.b(userId.longValue(), (OldHomeFragment) this.a, (SharedPreferences) this.b, (EventLogger) this.c, (c) this.d);
        if (((com.quizlet.quizletandroid.ui.promo.rateus.a) bVar.e.get()) == null) {
            c4885d = p.f(Boolean.FALSE);
        } else {
            Z zP = i.p(Boolean.valueOf(!bVar.a.contains("RateUsPromoDismissed")));
            StringBuilder sb = new StringBuilder("RateUsPromoSessionCount_");
            d dVar = bVar.c;
            sb.append(dVar.a);
            c4885d = new C4885d(i.n(zP, i.p(Boolean.valueOf(dVar.b.getInt(sb.toString(), 0) >= 3)), bVar.d.u().g(new com.quizlet.infra.legacysyncengine.models.serializers.a(24)).m()).m(io.reactivex.rxjava3.internal.functions.d.a, 3), new com.quizlet.infra.legacysyncengine.models.serializers.a(25), i2);
        }
        return c4885d.g(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(bVar, i));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r7 instanceof androidx.datastore.core.C1077i
            if (r0 == 0) goto L13
            r0 = r7
            androidx.datastore.core.i r0 = (androidx.datastore.core.C1077i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.datastore.core.i r0 = new androidx.datastore.core.i
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.data.repository.explanations.exercise.b r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L64
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L34:
            com.quizlet.data.repository.explanations.exercise.b r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L74
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.c
            java.util.List r7 = (java.util.List) r7
            java.lang.Object r2 = r6.d
            androidx.datastore.core.P r2 = (androidx.datastore.core.P) r2
            if (r7 == 0) goto L67
            boolean r7 = r7.isEmpty()
            if (r7 == 0) goto L4e
            goto L67
        L4e:
            androidx.datastore.core.k0 r7 = r2.g()
            androidx.datastore.core.l r4 = new androidx.datastore.core.l
            r5 = 0
            r4.<init>(r2, r6, r5)
            r0.j = r6
            r0.m = r3
            java.lang.Object r7 = r7.b(r4, r0)
            if (r7 != r1) goto L63
            goto L72
        L63:
            r0 = r6
        L64:
            androidx.datastore.core.c r7 = (androidx.datastore.core.C1071c) r7
            goto L76
        L67:
            r0.j = r6
            r0.m = r4
            r7 = 0
            java.lang.Object r7 = androidx.datastore.core.P.f(r2, r7, r0)
            if (r7 != r1) goto L73
        L72:
            return r1
        L73:
            r0 = r6
        L74:
            androidx.datastore.core.c r7 = (androidx.datastore.core.C1071c) r7
        L76:
            java.lang.Object r0 = r0.d
            androidx.datastore.core.P r0 = (androidx.datastore.core.P) r0
            androidx.webkit.internal.p r0 = r0.h
            r0.w(r7)
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.explanations.exercise.b.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
        Vp vp = (Vp) this.a;
        interfaceC2529qe.f0(vp, (Xp) this.b);
        C1669Be c1669BeL = interfaceC2529qe.L();
        C2601s7 c2601s7 = AbstractC2773w7.ea;
        r rVar = r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && c1669BeL != null) {
            C1843ak c1843ak = (C1843ak) this.d;
            C2584rr c2584rr = c1843ak.j;
            C2830xf c2830xf = (C2830xf) this.c;
            C2107gm c2107gm = c1843ak.i;
            c1669BeL.b(c2830xf, c2107gm, c2584rr);
            c1669BeL.d(c2830xf, c2107gm, c1843ak.d);
        }
        if (!((Boolean) rVar.c.a(AbstractC2773w7.Vc)).booleanValue() || c1669BeL == null) {
            return;
        }
        C1739Nc c1739Nc = j.C.y;
        C2743ve c2743ve = c1669BeL.a;
        if (c1739Nc.e(c2743ve.getContext())) {
            c1669BeL.j("/logScionEvent");
            new HashMap();
            c1669BeL.a("/logScionEvent", new C2217j9(1, c2743ve.getContext(), vp.w0));
        }
    }

    public synchronized ExecutorService d() {
        ThreadPoolExecutor threadPoolExecutor;
        try {
            if (((ThreadPoolExecutor) this.a) == null) {
                TimeUnit timeUnit = TimeUnit.SECONDS;
                SynchronousQueue synchronousQueue = new SynchronousQueue();
                String name = okhttp3.internal.b.g + " Dispatcher";
                Intrinsics.checkNotNullParameter(name, "name");
                this.a = new ThreadPoolExecutor(0, SubsamplingScaleImageView.TILE_SIZE_AUTO, 60L, timeUnit, synchronousQueue, new okhttp3.internal.a(name, false));
            }
            threadPoolExecutor = (ThreadPoolExecutor) this.a;
            Intrinsics.d(threadPoolExecutor);
        } catch (Throwable th) {
            throw th;
        }
        return threadPoolExecutor;
    }

    public void e(ArrayDeque arrayDeque, Object obj) {
        synchronized (this) {
            if (!arrayDeque.remove(obj)) {
                throw new AssertionError("Call wasn't in-flight!");
            }
            Unit unit = Unit.a;
        }
        g();
    }

    public void f(okhttp3.internal.connection.d call) {
        Intrinsics.checkNotNullParameter(call, "call");
        call.b.decrementAndGet();
        e((ArrayDeque) this.c, call);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x006a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void g() {
        /*
            r8 = this;
            byte[] r0 = okhttp3.internal.b.a
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            monitor-enter(r8)
            java.lang.Object r1 = r8.b     // Catch: java.lang.Throwable -> L4e
            java.util.ArrayDeque r1 = (java.util.ArrayDeque) r1     // Catch: java.lang.Throwable -> L4e
            java.util.Iterator r1 = r1.iterator()     // Catch: java.lang.Throwable -> L4e
            java.lang.String r2 = "readyAsyncCalls.iterator()"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)     // Catch: java.lang.Throwable -> L4e
        L15:
            boolean r2 = r1.hasNext()     // Catch: java.lang.Throwable -> L4e
            if (r2 == 0) goto L50
            java.lang.Object r2 = r1.next()     // Catch: java.lang.Throwable -> L4e
            okhttp3.internal.connection.d r2 = (okhttp3.internal.connection.d) r2     // Catch: java.lang.Throwable -> L4e
            java.lang.Object r3 = r8.c     // Catch: java.lang.Throwable -> L4e
            java.util.ArrayDeque r3 = (java.util.ArrayDeque) r3     // Catch: java.lang.Throwable -> L4e
            int r3 = r3.size()     // Catch: java.lang.Throwable -> L4e
            r4 = 64
            if (r3 >= r4) goto L50
            java.util.concurrent.atomic.AtomicInteger r3 = r2.b     // Catch: java.lang.Throwable -> L4e
            int r3 = r3.get()     // Catch: java.lang.Throwable -> L4e
            r4 = 5
            if (r3 >= r4) goto L15
            r1.remove()     // Catch: java.lang.Throwable -> L4e
            java.util.concurrent.atomic.AtomicInteger r3 = r2.b     // Catch: java.lang.Throwable -> L4e
            r3.incrementAndGet()     // Catch: java.lang.Throwable -> L4e
            java.lang.String r3 = "asyncCall"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)     // Catch: java.lang.Throwable -> L4e
            r0.add(r2)     // Catch: java.lang.Throwable -> L4e
            java.lang.Object r3 = r8.c     // Catch: java.lang.Throwable -> L4e
            java.util.ArrayDeque r3 = (java.util.ArrayDeque) r3     // Catch: java.lang.Throwable -> L4e
            r3.add(r2)     // Catch: java.lang.Throwable -> L4e
            goto L15
        L4e:
            r0 = move-exception
            goto Lb4
        L50:
            monitor-enter(r8)     // Catch: java.lang.Throwable -> L4e
            java.lang.Object r1 = r8.c     // Catch: java.lang.Throwable -> Lb1
            java.util.ArrayDeque r1 = (java.util.ArrayDeque) r1     // Catch: java.lang.Throwable -> Lb1
            r1.size()     // Catch: java.lang.Throwable -> Lb1
            java.lang.Object r1 = r8.d     // Catch: java.lang.Throwable -> Lb1
            java.util.ArrayDeque r1 = (java.util.ArrayDeque) r1     // Catch: java.lang.Throwable -> Lb1
            r1.size()     // Catch: java.lang.Throwable -> Lb1
            monitor-exit(r8)     // Catch: java.lang.Throwable -> L4e
            kotlin.Unit r1 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L4e
            monitor-exit(r8)
            int r1 = r0.size()
            r2 = 0
        L68:
            if (r2 >= r1) goto Lb0
            java.lang.Object r3 = r0.get(r2)
            okhttp3.internal.connection.d r3 = (okhttp3.internal.connection.d) r3
            java.util.concurrent.ExecutorService r4 = r8.d()
            r3.getClass()
            java.lang.String r5 = "executorService"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)
            okhttp3.internal.connection.g r5 = r3.c
            okhttp3.A r6 = r5.a
            com.quizlet.data.repository.explanations.exercise.b r6 = r6.a
            byte[] r6 = okhttp3.internal.b.a
            java.util.concurrent.ThreadPoolExecutor r4 = (java.util.concurrent.ThreadPoolExecutor) r4     // Catch: java.util.concurrent.RejectedExecutionException -> L8a java.lang.Throwable -> La7
            r4.execute(r3)     // Catch: java.util.concurrent.RejectedExecutionException -> L8a java.lang.Throwable -> La7
            goto La4
        L8a:
            r4 = move-exception
            java.io.InterruptedIOException r6 = new java.io.InterruptedIOException     // Catch: java.lang.Throwable -> La7
            java.lang.String r7 = "executor rejected"
            r6.<init>(r7)     // Catch: java.lang.Throwable -> La7
            r6.initCause(r4)     // Catch: java.lang.Throwable -> La7
            r5.k(r6)     // Catch: java.lang.Throwable -> La7
            okhttp3.f r4 = r3.a     // Catch: java.lang.Throwable -> La7
            r4.onFailure(r5, r6)     // Catch: java.lang.Throwable -> La7
            okhttp3.A r4 = r5.a
            com.quizlet.data.repository.explanations.exercise.b r4 = r4.a
            r4.f(r3)
        La4:
            int r2 = r2 + 1
            goto L68
        La7:
            r0 = move-exception
            okhttp3.A r1 = r5.a
            com.quizlet.data.repository.explanations.exercise.b r1 = r1.a
            r1.f(r3)
            throw r0
        Lb0:
            return
        Lb1:
            r0 = move-exception
            monitor-exit(r8)     // Catch: java.lang.Throwable -> Lb1
            throw r0     // Catch: java.lang.Throwable -> L4e
        Lb4:
            monitor-exit(r8)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.explanations.exercise.b.g():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v5, types: [kotlinx.coroutines.sync.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r7 instanceof androidx.datastore.core.e0
            if (r0 == 0) goto L13
            r0 = r7
            androidx.datastore.core.e0 r0 = (androidx.datastore.core.e0) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.datastore.core.e0 r0 = new androidx.datastore.core.e0
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L43
            if (r2 == r4) goto L3a
            if (r2 != r3) goto L32
            kotlinx.coroutines.sync.a r1 = r0.k
            com.quizlet.data.repository.explanations.exercise.b r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L2f
            goto L8a
        L2f:
            r7 = move-exception
            goto L99
        L32:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L3a:
            kotlinx.coroutines.sync.a r2 = r0.k
            com.quizlet.data.repository.explanations.exercise.b r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r7 = r2
            goto L65
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.b
            kotlinx.coroutines.r r7 = (kotlinx.coroutines.r) r7
            boolean r7 = r7.d0()
            if (r7 == 0) goto L53
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L53:
            r0.j = r6
            java.lang.Object r7 = r6.a
            kotlinx.coroutines.sync.c r7 = (kotlinx.coroutines.sync.c) r7
            r0.k = r7
            r0.n = r4
            java.lang.Object r2 = r7.d(r0)
            if (r2 != r1) goto L64
            goto L87
        L64:
            r4 = r6
        L65:
            java.lang.Object r2 = r4.b     // Catch: java.lang.Throwable -> L77
            kotlinx.coroutines.r r2 = (kotlinx.coroutines.r) r2     // Catch: java.lang.Throwable -> L77
            boolean r2 = r2.d0()     // Catch: java.lang.Throwable -> L77
            if (r2 == 0) goto L7b
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L77
            kotlinx.coroutines.sync.c r7 = (kotlinx.coroutines.sync.c) r7
            r7.f(r5)
            return r0
        L77:
            r0 = move-exception
            r1 = r7
            r7 = r0
            goto L99
        L7b:
            r0.j = r4     // Catch: java.lang.Throwable -> L77
            r0.k = r7     // Catch: java.lang.Throwable -> L77
            r0.n = r3     // Catch: java.lang.Throwable -> L77
            java.lang.Object r0 = r4.b(r0)     // Catch: java.lang.Throwable -> L77
            if (r0 != r1) goto L88
        L87:
            return r1
        L88:
            r1 = r7
            r0 = r4
        L8a:
            java.lang.Object r7 = r0.b     // Catch: java.lang.Throwable -> L2f
            kotlinx.coroutines.r r7 = (kotlinx.coroutines.r) r7     // Catch: java.lang.Throwable -> L2f
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2f
            r7.U(r0)     // Catch: java.lang.Throwable -> L2f
            kotlinx.coroutines.sync.c r1 = (kotlinx.coroutines.sync.c) r1
            r1.f(r5)
            return r0
        L99:
            kotlinx.coroutines.sync.c r1 = (kotlinx.coroutines.sync.c) r1
            r1.f(r5)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.explanations.exercise.b.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public synchronized void i(MotionEvent motionEvent) {
        try {
            long jCurrentTimeMillis = System.currentTimeMillis();
            HashMap map = new HashMap();
            map.put("t", new Throwable());
            map.put("aid", null);
            map.put("evt", motionEvent);
            Object obj = this.a;
            obj.getClass().getDeclaredMethod("he", Map.class).invoke(obj, map);
            ((k) this.d).s(3003, System.currentTimeMillis() - jCurrentTimeMillis);
        } catch (Exception e) {
            throw new zzfps(2005, e);
        }
    }

    public synchronized int j() {
        Object obj;
        try {
            obj = this.a;
        } catch (Exception e) {
            throw new zzfps(2006, e);
        }
        return ((Integer) obj.getClass().getDeclaredMethod("lcs", null).invoke(obj, null)).intValue();
    }

    public synchronized void k() {
        try {
            long jCurrentTimeMillis = System.currentTimeMillis();
            Object obj = this.a;
            obj.getClass().getDeclaredMethod("close", null).invoke(obj, null);
            ((k) this.d).s(com.pubmatic.sdk.common.h.CLIENT_SIDE_AUCTION_LOST, System.currentTimeMillis() - jCurrentTimeMillis);
        } catch (Exception e) {
            throw new zzfps(2003, e);
        }
    }

    public synchronized boolean l() {
        Object obj;
        try {
            obj = this.a;
        } catch (Exception e) {
            throw new zzfps(com.pubmatic.sdk.common.h.AD_ALREADY_SHOWN, e);
        }
        return ((Boolean) obj.getClass().getDeclaredMethod("init", null).invoke(obj, null)).booleanValue();
    }

    public synchronized byte[] n(HashMap map) {
        Object obj;
        long jCurrentTimeMillis = System.currentTimeMillis();
        try {
            obj = this.a;
        } catch (Exception e) {
            ((k) this.d).r(2007, System.currentTimeMillis() - jCurrentTimeMillis, e);
            return null;
        }
        return (byte[]) obj.getClass().getDeclaredMethod("xss", Map.class, Map.class).invoke(obj, null, map);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
    }

    public /* synthetic */ b(Object obj, Object obj2, Object obj3, Object obj4) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
    }

    public b(int i) {
        switch (i) {
            case 8:
                this.b = new ArrayDeque();
                this.c = new ArrayDeque();
                this.d = new ArrayDeque();
                break;
            default:
                this.a = new Kn();
                this.b = new Kn();
                this.c = new C2253k2();
                break;
        }
    }

    public b(com.quizlet.data.interactor.progress.c progressResetUseCase, long j, long j2) {
        Intrinsics.checkNotNullParameter(progressResetUseCase, "progressResetUseCase");
        com.quizlet.data.interactor.progress.d getObservableFunc = new com.quizlet.data.interactor.progress.d(progressResetUseCase, j, j2);
        Intrinsics.checkNotNullParameter(getObservableFunc, "getObservableFunc");
        this.a = getObservableFunc;
        this.b = com.google.android.gms.measurement.internal.Z.f("create(...)");
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.c = dVarZ;
        i iVarM = dVarZ.m(new com.google.mlkit.vision.documentscanner.internal.c(this, 5), SubsamplingScaleImageView.TILE_SIZE_AUTO);
        Intrinsics.checkNotNullExpressionValue(iVarM, "flatMap(...)");
        this.d = iVarM;
    }

    public b(com.quizlet.data.interactor.course.a dataStoreFactory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        Intrinsics.checkNotNullParameter(dataStoreFactory, "dataStoreFactory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = dataStoreFactory;
        this.b = networkStatus;
        this.c = logger;
        this.d = new LinkedHashMap();
    }

    public b(P p, List initTasksList) {
        Intrinsics.checkNotNullParameter(initTasksList, "initTasksList");
        this.d = p;
        this.a = kotlinx.coroutines.sync.d.a();
        this.b = E.b();
        this.c = CollectionsKt.w0(initTasksList);
    }
}
