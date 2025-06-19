package androidx.work.impl.model;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowInsetsAnimation;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.h0;
import androidx.camera.core.impl.EnumC0174m;
import androidx.camera.core.impl.EnumC0175n;
import androidx.camera.core.impl.EnumC0176o;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.v0;
import androidx.compose.animation.D;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.pager.C0472k;
import androidx.compose.foundation.pager.x;
import androidx.compose.foundation.pager.z;
import androidx.compose.runtime.L0;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.InterfaceC0920p;
import androidx.compose.ui.node.L;
import androidx.datastore.core.InterfaceC1076h;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.C;
import androidx.work.impl.WorkDatabase_Impl;
import assistantMode.refactored.types.StudiableData;
import com.bumptech.glide.Glide;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3110c0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.measurement.internal.g1;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.I0;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBProgressReset;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes.dex */
public class e implements InterfaceC0177p, androidx.camera.core.impl.utils.futures.c, androidx.compose.foundation.gestures.snapping.m, InterfaceC5182g, io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.i {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ e(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v0 */
    /* JADX WARN: Type inference failed for: r5v1, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v3 */
    /* JADX WARN: Type inference failed for: r5v4, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v6 */
    /* JADX WARN: Type inference failed for: r5v7 */
    /* JADX WARN: Type inference failed for: r5v8 */
    /* JADX WARN: Type inference failed for: r5v9 */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1 */
    /* JADX WARN: Type inference failed for: r6v10 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v2 */
    /* JADX WARN: Type inference failed for: r6v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9 */
    public static void n(E e) {
        L l = e.x;
        int i = 0;
        if (l.c == 5 && !l.e && !l.d && !e.G && e.F()) {
            androidx.compose.ui.p pVar = (androidx.compose.ui.p) e.w.f;
            if ((pVar.d & 256) != 0) {
                while (pVar != null) {
                    if ((pVar.c & 256) != 0) {
                        AbstractC0918n abstractC0918nF = pVar;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof InterfaceC0920p) {
                                InterfaceC0920p interfaceC0920p = (InterfaceC0920p) abstractC0918nF;
                                interfaceC0920p.y0(AbstractC0910f.t(interfaceC0920p, 256));
                            } else if ((abstractC0918nF.c & 256) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar2 = abstractC0918nF.o;
                                int i2 = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                                while (pVar2 != null) {
                                    if ((pVar2.c & 256) != 0) {
                                        i2++;
                                        bVar = bVar;
                                        if (i2 == 1) {
                                            abstractC0918nF = pVar2;
                                        } else {
                                            if (bVar == 0) {
                                                bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (abstractC0918nF != 0) {
                                                bVar.b(abstractC0918nF);
                                                abstractC0918nF = 0;
                                            }
                                            bVar.b(pVar2);
                                        }
                                    }
                                    pVar2 = pVar2.f;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                }
                                if (i2 == 1) {
                                }
                            }
                            abstractC0918nF = AbstractC0910f.f(bVar);
                        }
                    }
                    if ((pVar.d & 256) == 0) {
                        break;
                    } else {
                        pVar = pVar.f;
                    }
                }
            }
        }
        e.F = false;
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i3 = bVarW.c;
        if (i3 > 0) {
            Object[] objArr = bVarW.a;
            do {
                n((E) objArr[i]);
                i++;
            } while (i < i3);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0021, code lost:
    
        if (r0.length() != 0) goto L14;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.List w(com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t r4, com.quizlet.generated.enums.w1 r5) {
        /*
            java.util.ArrayList r0 = r4.a
            boolean r0 = r0.isEmpty()
            if (r0 != 0) goto L7f
            com.quizlet.quizletandroid.ui.startpage.nav2.model.b r0 = com.quizlet.quizletandroid.ui.startpage.nav2.model.C4706b.a
            com.google.android.gms.internal.mlkit_vision_document_scanner.d6 r1 = r4.b
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r1, r0)
            if (r0 == 0) goto L13
            goto L24
        L13:
            if (r1 == 0) goto L1a
            java.lang.String r0 = r1.c()
            goto L1b
        L1a:
            r0 = 0
        L1b:
            if (r0 == 0) goto L7f
            int r0 = r0.length()
            if (r0 != 0) goto L24
            goto L7f
        L24:
            java.lang.String r0 = "subplacement"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            int[] r0 = com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4722s.a
            int r2 = r5.ordinal()
            r0 = r0[r2]
            java.util.ArrayList r4 = r4.a
            r2 = 1
            r3 = 6
            if (r0 == r2) goto L6d
            r2 = 2
            if (r0 == r2) goto L5f
            r2 = 3
            if (r0 != r2) goto L4b
            com.quizlet.quizletandroid.ui.startpage.nav2.model.w r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.w
            java.util.List r4 = kotlin.collections.CollectionsKt.p0(r4, r3)
            java.util.ArrayList r4 = com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t.a(r4, r5)
            r0.<init>(r4, r1)
            goto L7a
        L4b:
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "Invalid subplacement: "
            r0.<init>(r1)
            r0.append(r5)
            java.lang.String r5 = r0.toString()
            r4.<init>(r5)
            throw r4
        L5f:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.D r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.D
            java.util.List r4 = kotlin.collections.CollectionsKt.p0(r4, r3)
            java.util.ArrayList r4 = com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t.a(r4, r5)
            r0.<init>(r4, r1)
            goto L7a
        L6d:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.x r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.x
            java.util.List r4 = kotlin.collections.CollectionsKt.p0(r4, r3)
            java.util.ArrayList r4 = com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t.a(r4, r5)
            r0.<init>(r4, r1)
        L7a:
            java.util.List r4 = kotlin.collections.A.b(r0)
            return r4
        L7f:
            kotlin.collections.K r4 = kotlin.collections.K.a
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.w(com.quizlet.quizletandroid.ui.startpage.nav2.model.t, com.quizlet.generated.enums.w1):java.util.List");
    }

    public static com.google.android.gms.analytics.f x(Class cls) {
        try {
            return (com.google.android.gms.analytics.f) cls.getDeclaredConstructor(null).newInstance(null);
        } catch (Exception e) {
            if (e instanceof InstantiationException) {
                throw new IllegalArgumentException("dataType doesn't have default constructor", e);
            }
            if (e instanceof IllegalAccessException) {
                throw new IllegalArgumentException("dataType default constructor is not accessible", e);
            }
            if (e instanceof ReflectiveOperationException) {
                throw new IllegalArgumentException("Linkage exception", e);
            }
            throw new RuntimeException(e);
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public long a() {
        Long l = (Long) ((TotalCaptureResult) this.c).get(CaptureResult.SENSOR_TIMESTAMP);
        if (l == null) {
            return -1L;
        }
        return l.longValue();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case EventType.AUDIO /* 23 */:
                I0 optionalRecord = (I0) obj;
                Intrinsics.checkNotNullParameter(optionalRecord, "optionalRecord");
                optionalRecord.getClass();
                DBProgressReset dBProgressReset = (DBProgressReset) (optionalRecord instanceof C4116c1 ? ((C4116c1) optionalRecord).a : null);
                C4127f1 data = (C4127f1) this.c;
                com.quizlet.data.repository.folderwithcreator.e eVar = (com.quizlet.data.repository.folderwithcreator.e) this.b;
                if (dBProgressReset != null) {
                    Object obj2 = eVar.d;
                    boolean zEquals = com.quizlet.shared.usecase.folderstudymaterials.c.q(dBProgressReset).equals(data);
                    io.reactivex.rxjava3.internal.operators.completable.f fVar = io.reactivex.rxjava3.internal.operators.completable.f.a;
                    if (zEquals) {
                        return fVar;
                    }
                    long resetTimeSec = dBProgressReset.getResetTimeSec();
                    Long l = data.d;
                    if (resetTimeSec > (l != null ? l.longValue() : 0L)) {
                        return fVar;
                    }
                }
                Object obj3 = eVar.d;
                Intrinsics.checkNotNullParameter(data, "data");
                DBProgressReset dBProgressReset2 = new DBProgressReset();
                dBProgressReset2.setPersonId(data.a);
                dBProgressReset2.setContainerId(data.b);
                dBProgressReset2.setContainerType((short) data.c.b());
                Long l2 = data.d;
                dBProgressReset2.setResetTimeSec(l2 != null ? l2.longValue() : 0L);
                if (dBProgressReset != null) {
                    dBProgressReset2.setLocalId(dBProgressReset.getLocalId());
                }
                io.reactivex.rxjava3.core.p pVarGenerateLocalIdIfNeededAsync = ((ModelIdentityProvider) eVar.c).generateLocalIdIfNeededAsync(dBProgressReset2);
                com.google.firebase.crashlytics.internal.common.j jVar = new com.google.firebase.crashlytics.internal.common.j(eVar, 23);
                pVarGenerateLocalIdIfNeededAsync.getClass();
                io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(5, pVarGenerateLocalIdIfNeededAsync, jVar);
                Intrinsics.checkNotNullExpressionValue(aVar, "flatMapCompletable(...)");
                return aVar;
            default:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                return new io.reactivex.rxjava3.internal.operators.maybe.h(0, new C4885d(new J(io.reactivex.rxjava3.core.i.o(list), new c(26, (com.google.android.datatransport.cct.internal.s) this.b, (com.quizlet.quizletandroid.data.management.a) this.c), 1), com.quizlet.quizletandroid.data.management.c.j, 0), com.quizlet.quizletandroid.data.management.c.k);
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public v0 b() {
        return (v0) this.b;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0176o c() {
        Integer num = (Integer) ((TotalCaptureResult) this.c).get(CaptureResult.CONTROL_AWB_STATE);
        EnumC0176o enumC0176o = EnumC0176o.a;
        if (num == null) {
            return enumC0176o;
        }
        int iIntValue = num.intValue();
        if (iIntValue == 0) {
            return EnumC0176o.b;
        }
        if (iIntValue == 1) {
            return EnumC0176o.c;
        }
        if (iIntValue == 2) {
            return EnumC0176o.d;
        }
        if (iIntValue == 3) {
            return EnumC0176o.e;
        }
        AbstractC3053s1.c("C2CameraCaptureResult", "Undefined awb state: " + num);
        return enumC0176o;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0174m d() {
        Integer num = (Integer) ((TotalCaptureResult) this.c).get(CaptureResult.CONTROL_AE_STATE);
        EnumC0174m enumC0174m = EnumC0174m.a;
        if (num == null) {
            return enumC0174m;
        }
        int iIntValue = num.intValue();
        if (iIntValue == 0) {
            return EnumC0174m.b;
        }
        if (iIntValue != 1) {
            if (iIntValue == 2) {
                return EnumC0174m.e;
            }
            if (iIntValue == 3) {
                return EnumC0174m.f;
            }
            if (iIntValue == 4) {
                return EnumC0174m.d;
            }
            if (iIntValue != 5) {
                AbstractC3053s1.c("C2CameraCaptureResult", "Undefined ae state: " + num);
                return enumC0174m;
            }
        }
        return EnumC0174m.c;
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public CaptureResult e() {
        return (TotalCaptureResult) this.c;
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) throws JSONException {
        OTLogger.c("NetworkRequestHandler", 6, "IAB Vendor Disclosure API Failed :  " + th.getMessage());
        ((T) this.c).f(new JSONObject());
    }

    @Override // androidx.camera.core.impl.InterfaceC0177p
    public EnumC0175n g() {
        Integer num = (Integer) ((TotalCaptureResult) this.c).get(CaptureResult.CONTROL_AF_STATE);
        EnumC0175n enumC0175n = EnumC0175n.a;
        if (num == null) {
            return enumC0175n;
        }
        switch (num.intValue()) {
            case 0:
                break;
            case 1:
            case 3:
                break;
            case 2:
                break;
            case 4:
                break;
            case 5:
                break;
            case 6:
                break;
            default:
                AbstractC3053s1.c("C2CameraCaptureResult", "Undefined af state: " + num);
                break;
        }
        return enumC0175n;
    }

    @Override // androidx.compose.foundation.gestures.snapping.m
    public float h(float f, float f2) {
        C0466e c0466e = (C0466e) this.b;
        int iM = ((x) ((L0) c0466e.o).getValue()).c + c0466e.m();
        if (iM == 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        int i = f < DefinitionKt.NO_Float_VALUE ? c0466e.d + 1 : c0466e.d;
        int iC = kotlin.ranges.l.c(((int) (f2 / iM)) + i, 0, c0466e.l());
        c0466e.m();
        int i2 = ((x) ((L0) c0466e.o).getValue()).c;
        long j = i;
        long j2 = 1;
        long j3 = j - j2;
        if (j3 < 0) {
            j3 = 0;
        }
        int i3 = (int) j3;
        long j4 = j + j2;
        if (j4 > 2147483647L) {
            j4 = 2147483647L;
        }
        int iAbs = Math.abs((kotlin.ranges.l.c(kotlin.ranges.l.c(iC, i3, (int) j4), 0, c0466e.l()) - i) * iM) - iM;
        int i4 = iAbs >= 0 ? iAbs : 0;
        if (i4 == 0) {
            return i4;
        }
        return Math.signum(f) * i4;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(androidx.work.impl.model.c r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r11 = this;
            boolean r0 = r13 instanceof com.quizlet.features.onboarding.flashcards.i
            if (r0 == 0) goto L13
            r0 = r13
            com.quizlet.features.onboarding.flashcards.i r0 = (com.quizlet.features.onboarding.flashcards.i) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.onboarding.flashcards.i r0 = new com.quizlet.features.onboarding.flashcards.i
            r0.<init>(r11, r13)
        L18:
            java.lang.Object r13 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 4
            r4 = 3
            r5 = 2
            r6 = 1
            r7 = 0
            if (r2 == 0) goto L54
            if (r2 == r6) goto L4c
            if (r2 == r5) goto L42
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            androidx.glance.appwidget.protobuf.Z.e(r13)
            return r13
        L31:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r13 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r13)
            throw r12
        L39:
            androidx.work.impl.model.c r12 = r0.k
            androidx.work.impl.model.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto La9
        L42:
            com.google.mlkit.vision.documentscanner.internal.c r12 = r0.l
            androidx.work.impl.model.c r2 = r0.k
            androidx.work.impl.model.e r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L8d
        L4c:
            androidx.work.impl.model.c r12 = r0.k
            androidx.work.impl.model.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L69
        L54:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r0.j = r11
            r0.k = r12
            r0.o = r6
            java.lang.Object r13 = r11.b
            com.quizlet.data.repository.user.a r13 = (com.quizlet.data.repository.user.a) r13
            java.lang.Object r13 = r13.j(r0)
            if (r13 != r1) goto L68
            goto Lc2
        L68:
            r2 = r11
        L69:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            if (r13 == 0) goto Lc4
            java.lang.Object r13 = r2.c
            com.google.mlkit.vision.documentscanner.internal.c r13 = (com.google.mlkit.vision.documentscanner.internal.c) r13
            io.reactivex.rxjava3.internal.operators.single.g r6 = r12.n()
            r0.j = r2
            r0.k = r12
            r0.l = r13
            r0.o = r5
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r5 != r1) goto L88
            goto Lc2
        L88:
            r10 = r2
            r2 = r12
            r12 = r13
            r13 = r5
            r5 = r10
        L8d:
            java.lang.String r6 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r13, r6)
            java.lang.Number r13 = (java.lang.Number) r13
            long r8 = r13.longValue()
            r0.j = r5
            r0.k = r2
            r0.l = r7
            r0.o = r4
            java.lang.Object r13 = r12.l(r8, r0)
            if (r13 != r1) goto La7
            goto Lc2
        La7:
            r12 = r2
            r2 = r5
        La9:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r13 = r13.booleanValue()
            if (r13 != 0) goto Lc4
            r2.getClass()
            com.quizlet.time.b r13 = com.quizlet.time.b.a
            r0.j = r7
            r0.k = r7
            r0.o = r3
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_camera.J1.b(r12, r13, r0)
            if (r12 != r1) goto Lc3
        Lc2:
            return r1
        Lc3:
            return r12
        Lc4:
            java.lang.Boolean r12 = java.lang.Boolean.FALSE
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.i(androidx.work.impl.model.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.gestures.snapping.m
    public float j(float f) {
        C0466e c0466e = (C0466e) this.b;
        androidx.compose.foundation.gestures.snapping.n nVar = c0466e.k().n;
        ?? r3 = c0466e.k().a;
        int size = r3.size();
        float f2 = Float.POSITIVE_INFINITY;
        float f3 = Float.NEGATIVE_INFINITY;
        for (int i = 0; i < size; i++) {
            C0472k c0472k = (C0472k) r3.get(i);
            x xVarK = c0466e.k();
            EnumC0320d0 enumC0320d0 = xVarK.e;
            EnumC0320d0 enumC0320d02 = EnumC0320d0.a;
            xVarK.a();
            int i2 = c0466e.k().f;
            int i3 = c0466e.k().d;
            int i4 = c0466e.k().b;
            int i5 = c0472k.l;
            c0466e.l();
            nVar.getClass();
            float f4 = i5 - 0;
            if (f4 <= DefinitionKt.NO_Float_VALUE && f4 > f3) {
                f3 = f4;
            }
            if (f4 >= DefinitionKt.NO_Float_VALUE && f4 < f2) {
                f2 = f4;
            }
        }
        if (f3 == Float.NEGATIVE_INFINITY) {
            f3 = f2;
        }
        if (f2 == Float.POSITIVE_INFINITY) {
            f2 = f3;
        }
        boolean z = AbstractC3110c0.b(c0466e) == DefinitionKt.NO_Float_VALUE;
        if (!c0466e.d()) {
            if (z || !AbstractC3110c0.d(c0466e)) {
                f2 = 0.0f;
            } else {
                f3 = 0.0f;
                f2 = 0.0f;
            }
        }
        if (!c0466e.b()) {
            if (z || AbstractC3110c0.d(c0466e)) {
                f3 = 0.0f;
            } else {
                f3 = 0.0f;
                f2 = 0.0f;
            }
        }
        Float fValueOf = Float.valueOf(f3);
        Float fValueOf2 = Float.valueOf(f2);
        float fFloatValue = fValueOf.floatValue();
        float fFloatValue2 = fValueOf2.floatValue();
        float fFloatValue3 = ((Number) ((D) this.c).invoke(Float.valueOf(f), Float.valueOf(fFloatValue), Float.valueOf(fFloatValue2))).floatValue();
        if (fFloatValue3 == fFloatValue || fFloatValue3 == fFloatValue2 || fFloatValue3 == DefinitionKt.NO_Float_VALUE) {
            return (fFloatValue3 == Float.POSITIVE_INFINITY || fFloatValue3 == Float.NEGATIVE_INFINITY) ? DefinitionKt.NO_Float_VALUE : fFloatValue3;
        }
        throw new IllegalStateException(("Final Snapping Offset Should Be one of " + fFloatValue + ", " + fFloatValue2 + " or 0.0").toString());
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, K k) throws JSONException {
        T t = (T) this.c;
        JSONObject jSONObject = new JSONObject();
        JSONObject[] jSONObjectArr = (JSONObject[]) this.b;
        jSONObjectArr[0] = jSONObject;
        StringBuilder sb = new StringBuilder("IAB Vendor Disclosure API Success : ");
        Object obj = k.b;
        sb.append((String) obj);
        OTLogger.c("NetworkRequestHandler", 4, sb.toString());
        if (obj != null) {
            try {
                JSONObject jSONObject2 = new JSONObject((String) obj);
                jSONObjectArr[0] = jSONObject2;
                t.f(jSONObject2);
            } catch (JSONException e) {
                com.google.android.gms.internal.mlkit_vision_document_scanner.T.d(e, new StringBuilder("Error while fetching IAB Vendor Disclosure details:  "), "NetworkRequestHandler", 6);
                t.f(new JSONObject());
            }
        }
    }

    public Object l(kotlin.coroutines.h hVar) {
        return ((com.quizlet.data.repository.activitycenter.b) this.b).j((com.quizlet.generated.enums.I0) this.c, hVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v5, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r1v6, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r1v9, types: [java.util.List] */
    public ArrayList m() {
        ?? arrayList;
        ArrayList arrayList2 = new ArrayList();
        androidx.appcompat.app.L l = (androidx.appcompat.app.L) this.c;
        Context context = (Context) this.b;
        Class cls = (Class) l.b;
        Bundle bundle = null;
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager == null) {
                Log.w("ComponentDiscovery", "Context has no PackageManager.");
            } else {
                ServiceInfo serviceInfo = packageManager.getServiceInfo(new ComponentName(context, (Class<?>) cls), 128);
                if (serviceInfo == null) {
                    Log.w("ComponentDiscovery", cls + " has no service info.");
                } else {
                    bundle = serviceInfo.metaData;
                }
            }
        } catch (PackageManager.NameNotFoundException unused) {
            Log.w("ComponentDiscovery", "Application info not found.");
        }
        if (bundle == null) {
            Log.w("ComponentDiscovery", "Could not retrieve metadata, returning empty list of registrars.");
            arrayList = Collections.EMPTY_LIST;
        } else {
            arrayList = new ArrayList();
            for (String str : bundle.keySet()) {
                if ("com.google.firebase.components.ComponentRegistrar".equals(bundle.get(str)) && str.startsWith("com.google.firebase.components:")) {
                    arrayList.add(str.substring(31));
                }
            }
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(new com.google.firebase.components.c((String) it2.next(), 0));
        }
        return arrayList2;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.C4697f
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.ui.startpage.nav2.f r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.C4697f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.f r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.f
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.work.impl.model.e r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L44
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            r0.m = r3
            java.lang.Object r5 = r4.b
            com.google.android.gms.internal.ads.C3 r5 = (com.google.android.gms.internal.ads.C3) r5
            java.lang.Object r5 = r5.b(r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            r0 = r4
        L44:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.t r5 = (com.quizlet.quizletandroid.ui.startpage.nav2.model.C4723t) r5
            com.quizlet.generated.enums.w1 r1 = com.quizlet.generated.enums.w1.AGE_LOCATION_REC
            r0.getClass()
            java.util.List r5 = w(r5, r1)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.o(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        if (th instanceof h0) {
            AbstractC3242q6.h(null, ((androidx.concurrent.futures.l) this.c).cancel(false));
        } else {
            AbstractC3242q6.h(null, ((androidx.concurrent.futures.i) this.b).b(null));
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        AbstractC3242q6.h(null, ((androidx.concurrent.futures.i) this.b).b(null));
    }

    public Long p(String str) {
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT long_value FROM Preference where `key`=?");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            Long lValueOf = null;
            if (cursorN.moveToFirst() && !cursorN.isNull(0)) {
                lValueOf = Long.valueOf(cursorN.getLong(0));
            }
            return lValueOf;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object q(kotlin.coroutines.jvm.internal.c r12) {
        /*
            r11 = this;
            boolean r0 = r12 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.C4698g
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.quizletandroid.ui.startpage.nav2.g r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.C4698g) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.g r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.g
            r0.<init>(r11, r12)
        L18:
            java.lang.Object r12 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L3f
        L27:
            java.lang.IllegalStateException r12 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r12.<init>(r0)
            throw r12
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r0.l = r3
            java.lang.Object r12 = r11.b
            com.google.android.gms.internal.ads.C3 r12 = (com.google.android.gms.internal.ads.C3) r12
            java.lang.Object r12 = r12.c(r0)
            if (r12 != r1) goto L3f
            return r1
        L3f:
            java.util.List r12 = (java.util.List) r12
            boolean r0 = r12.isEmpty()
            if (r0 == 0) goto L4a
            kotlin.collections.K r12 = kotlin.collections.K.a
            return r12
        L4a:
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r12, r1)
            r0.<init>(r1)
            java.util.Iterator r12 = r12.iterator()
        L59:
            boolean r1 = r12.hasNext()
            if (r1 == 0) goto L95
            java.lang.Object r1 = r12.next()
            com.quizlet.data.model.NotesToValueInfo r1 = (com.quizlet.data.model.NotesToValueInfo) r1
            com.quizlet.quizletandroid.ui.startpage.nav2.model.G r2 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.G
            java.lang.String r3 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r3)
            java.lang.String r6 = r1.a
            com.quizlet.data.model.TitleInfo r3 = r1.c
            if (r3 == 0) goto L75
            java.lang.String r3 = r3.c
            goto L76
        L75:
            r3 = 0
        L76:
            if (r3 != 0) goto L7a
            java.lang.String r3 = ""
        L7a:
            r7 = r3
            com.quizlet.data.model.User r1 = r1.h
            java.lang.String r8 = r1.b
            int r5 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6.b(r1)
            com.quizlet.ui.models.content.carditem.d r4 = new com.quizlet.ui.models.content.carditem.d
            boolean r10 = r1.e
            java.lang.String r9 = r1.i
            r4.<init>(r5, r6, r7, r8, r9, r10)
            com.quizlet.generated.enums.w1 r1 = com.quizlet.generated.enums.w1.RECENT_FEED
            r2.<init>(r4, r1)
            r0.add(r2)
            goto L59
        L95:
            com.quizlet.quizletandroid.ui.startpage.nav2.model.B r12 = new com.quizlet.quizletandroid.ui.startpage.nav2.model.B
            r12.<init>(r0)
            java.util.List r12 = kotlin.collections.A.b(r12)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.q(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public com.bumptech.glide.m r(Context context, Glide glide, C c, AbstractC1136h0 abstractC1136h0, boolean z) {
        com.bumptech.glide.util.m.a();
        com.bumptech.glide.util.m.a();
        HashMap map = (HashMap) this.b;
        com.bumptech.glide.m mVar = (com.bumptech.glide.m) map.get(c);
        if (mVar != null) {
            return mVar;
        }
        com.bumptech.glide.manager.h hVar = new com.bumptech.glide.manager.h(c);
        com.google.firebase.perf.logging.b bVar = new com.google.firebase.perf.logging.b(this, abstractC1136h0);
        ((com.google.mlkit.common.internal.model.a) this.c).getClass();
        com.bumptech.glide.m mVar2 = new com.bumptech.glide.m(glide, hVar, bVar, context);
        map.put(c, mVar2);
        hVar.a(new com.bumptech.glide.manager.j(this, c));
        if (z) {
            mVar2.onStart();
        }
        return mVar2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0070, code lost:
    
        if (r9 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object s(boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r7 = this;
            boolean r0 = r9 instanceof com.quizlet.data.interactor.freetrial.a
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.data.interactor.freetrial.a r0 = (com.quizlet.data.interactor.freetrial.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.data.interactor.freetrial.a r0 = new com.quizlet.data.interactor.freetrial.a
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 0
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L3c
            if (r2 == r6) goto L34
            if (r2 != r5) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L73
        L2c:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L34:
            boolean r8 = r0.k
            androidx.work.impl.model.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4d
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7
            r0.k = r8
            r0.n = r6
            java.lang.Object r9 = r7.v(r0)
            if (r9 != r1) goto L4c
            goto L72
        L4c:
            r2 = r7
        L4d:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L5b
            com.quizlet.data.model.u2 r8 = new com.quizlet.data.model.u2
            r8.<init>(r4)
            return r8
        L5b:
            java.lang.Object r9 = r2.b
            com.quizlet.data.repository.user.a r9 = (com.quizlet.data.repository.user.a) r9
            r0.j = r3
            r0.n = r5
            com.quizlet.upgrade.data.e r2 = new com.quizlet.upgrade.data.e
            r2.<init>(r9, r8, r3)
            java.lang.Object r8 = r9.d
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r9 = kotlinx.coroutines.E.J(r8, r2, r0)
            if (r9 != r1) goto L73
        L72:
            return r1
        L73:
            java.util.List r9 = (java.util.List) r9
            java.util.Iterator r8 = r9.iterator()
        L79:
            boolean r0 = r8.hasNext()
            if (r0 == 0) goto L8f
            java.lang.Object r0 = r8.next()
            r1 = r0
            com.quizlet.data.model.billing.a r1 = (com.quizlet.data.model.billing.a) r1
            com.quizlet.data.model.billing.b r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6.b(r1)
            com.quizlet.data.model.billing.b r2 = com.quizlet.data.model.billing.b.b
            if (r1 != r2) goto L79
            goto L90
        L8f:
            r0 = r3
        L90:
            com.quizlet.data.model.billing.a r0 = (com.quizlet.data.model.billing.a) r0
            java.util.Iterator r8 = r9.iterator()
        L96:
            boolean r9 = r8.hasNext()
            if (r9 == 0) goto Lac
            java.lang.Object r9 = r8.next()
            r1 = r9
            com.quizlet.data.model.billing.a r1 = (com.quizlet.data.model.billing.a) r1
            com.quizlet.data.model.billing.b r1 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6.b(r1)
            com.quizlet.data.model.billing.b r2 = com.quizlet.data.model.billing.b.a
            if (r1 != r2) goto L96
            goto Lad
        Lac:
            r9 = r3
        Lad:
            com.quizlet.data.model.billing.a r9 = (com.quizlet.data.model.billing.a) r9
            if (r0 == 0) goto Lbb
            int r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6.a(r0)
            java.lang.Integer r3 = new java.lang.Integer
            r3.<init>(r8)
            goto Lc6
        Lbb:
            if (r9 == 0) goto Lc6
            int r8 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6.a(r9)
            java.lang.Integer r3 = new java.lang.Integer
            r3.<init>(r8)
        Lc6:
            com.quizlet.data.model.u2 r8 = new com.quizlet.data.model.u2
            if (r3 == 0) goto Lce
            int r4 = r3.intValue()
        Lce:
            r8.<init>(r4)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.s(boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void t(d dVar) {
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        workDatabase_Impl.c();
        try {
            ((b) this.c).p(dVar);
            workDatabase_Impl.p();
        } finally {
            workDatabase_Impl.k();
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        String url = (String) obj;
        Intrinsics.checkNotNullParameter(url, "url");
        io.reactivex.rxjava3.core.g gVarA = ((com.quizlet.offline.data.a) this.b).a(((com.quizlet.qutils.data.offline.d) this.c).a(url, com.quizlet.qutils.data.offline.b.c));
        io.reactivex.rxjava3.internal.observers.d dVar = new io.reactivex.rxjava3.internal.observers.d(1);
        gVarA.e(dVar);
        return dVar.b() != null;
    }

    public String toString() {
        switch (this.a) {
            case 5:
                return "Bounds{lower=" + ((androidx.core.graphics.e) this.b) + " upper=" + ((androidx.core.graphics.e) this.c) + "}";
            default:
                return super.toString();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object u(long r5, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folder.l
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folder.l r0 = (com.quizlet.data.interactor.folder.l) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.l r0 = new com.quizlet.data.interactor.folder.l
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.interactor.folder.m r7 = new com.quizlet.data.interactor.folder.m
            r2 = 0
            r7.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r7, r0)
            if (r7 != r1) goto L45
            return r1
        L45:
            java.lang.String r5 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.u(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0071, code lost:
    
        if (r7 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object v(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.freetrial.b
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.freetrial.b r0 = (com.quizlet.data.interactor.freetrial.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.freetrial.b r0 = new com.quizlet.data.interactor.freetrial.b
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L74
        L2a:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L32:
            androidx.work.impl.model.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.c
            androidx.work.impl.model.c r7 = (androidx.work.impl.model.c) r7
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.q()
            r0.j = r6
            r0.m = r4
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r7 != r1) goto L4e
            goto L73
        L4e:
            r2 = r6
        L4f:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L7e
            java.lang.Object r7 = r2.c
            androidx.work.impl.model.c r7 = (androidx.work.impl.model.c) r7
            com.quizlet.local.datastore.preferences.c0 r2 = new com.quizlet.local.datastore.preferences.c0
            r5 = 25
            r2.<init>(r5)
            java.lang.Boolean r5 = java.lang.Boolean.FALSE
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.o(r2, r5)
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r7 != r1) goto L74
        L73:
            return r1
        L74:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 != 0) goto L7d
            goto L7e
        L7d:
            r4 = 0
        L7e:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r4)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.e.v(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public e(com.android.billingclient.api.e eVar, ArrayList arrayList) {
        this.a = 7;
        this.b = arrayList;
        this.c = eVar;
    }

    public e(g1 g1Var) {
        this.a = 11;
        this.c = g1Var;
    }

    public e(com.quizlet.data.repository.course.membership.c cVar, com.google.android.gms.common.util.a aVar) {
        this.a = 9;
        com.google.android.gms.common.internal.u.h(cVar);
        com.google.android.gms.common.internal.u.h(aVar);
        this.b = new HashMap();
        this.c = new ArrayList();
    }

    public e(com.quizlet.local.ormlite.models.bookmark.a folderWithCreatorLocalDataStore, com.quizlet.remote.model.union.folderwithcreator.e folderWithCreatorRemoteDataStore) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(folderWithCreatorLocalDataStore, "folderWithCreatorLocalDataStore");
        Intrinsics.checkNotNullParameter(folderWithCreatorRemoteDataStore, "folderWithCreatorRemoteDataStore");
        this.b = folderWithCreatorLocalDataStore;
        this.c = folderWithCreatorRemoteDataStore;
    }

    public e(com.quizlet.data.repository.classfolder.e repository, c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public e(com.quizlet.data.repository.term.g termRepository, c dispatcher) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(termRepository, "termRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = termRepository;
        this.c = dispatcher;
    }

    public e(c dataSource, com.quizlet.data.repository.course.membership.c exerciseDetailsMapper, com.quizlet.quizletandroid.logging.initializer.a meteringInfoMapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(exerciseDetailsMapper, "exerciseDetailsMapper");
        Intrinsics.checkNotNullParameter(meteringInfoMapper, "meteringInfoMapper");
        this.b = dataSource;
        this.c = exerciseDetailsMapper;
    }

    public e(com.quizlet.data.repository.activitycenter.b eligibilityFeature, com.quizlet.generated.enums.I0 productFeature) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(eligibilityFeature, "eligibilityFeature");
        Intrinsics.checkNotNullParameter(productFeature, "productFeature");
        this.b = eligibilityFeature;
        this.c = productFeature;
    }

    public e(IQuizletApiClient apiClient, AbstractC5040y ioDispatcher) {
        this.a = 24;
        ApiErrorResolver errorResolver = ApiErrorResolver.a;
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(errorResolver, "errorResolver");
        this.b = apiClient;
        this.c = ioDispatcher;
    }

    public e(com.quizlet.data.repository.folder.i folderRepository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = folderRepository;
        this.c = ioDispatcher;
    }

    public e(AbstractC5040y dispatcher, com.quizlet.data.repository.user.a feature, com.google.mlkit.vision.documentscanner.internal.c onboardingFlashcardsPreferences) {
        this.a = 21;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(feature, "feature");
        Intrinsics.checkNotNullParameter(onboardingFlashcardsPreferences, "onboardingFlashcardsPreferences");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = feature;
        this.c = onboardingFlashcardsPreferences;
    }

    public e(com.quizlet.data.repository.user.a getEligibleUpgradePlansUseCase, c userProperties) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(getEligibleUpgradePlansUseCase, "getEligibleUpgradePlansUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.b = getEligibleUpgradePlansUseCase;
        this.c = userProperties;
    }

    public e(com.google.mlkit.common.internal.model.a aVar) {
        this.a = 8;
        this.b = new HashMap();
        this.c = aVar;
    }

    public e(StudiableData studiableData) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        this.b = assistantMode.refactored.shims.b.b(studiableData, true, null);
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 27:
                this.c = new io.reactivex.rxjava3.disposables.a();
                break;
            default:
                this.b = new androidx.compose.runtime.collection.b(new E[16]);
                break;
        }
    }

    public e(WorkDatabase_Impl database) {
        this.a = 0;
        this.b = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.c = new b(database, 1);
    }

    public e(com.squareup.moshi.l jsonAdapter, InterfaceC1076h dataStore) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(jsonAdapter, "jsonAdapter");
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.b = jsonAdapter;
        this.c = dataStore;
    }

    public e(C0466e c0466e, D d, z zVar) {
        this.a = 3;
        this.b = c0466e;
        this.c = d;
    }

    public e(C3 homeDataLoader, c userProperties) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(homeDataLoader, "homeDataLoader");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.b = homeDataLoader;
        this.c = userProperties;
    }

    public e(com.google.firebase.inject.b bVar) {
        this.a = 13;
        this.c = Collections.synchronizedMap(new HashMap());
        this.b = bVar;
    }

    public e(WindowInsetsAnimation.Bounds bounds) {
        this.a = 5;
        this.b = androidx.core.graphics.e.c(bounds.getLowerBound());
        this.c = androidx.core.graphics.e.c(bounds.getUpperBound());
    }
}
