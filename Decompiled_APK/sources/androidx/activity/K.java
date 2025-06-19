package androidx.activity;

import android.os.Build;
import android.os.Looper;
import android.view.View;
import android.view.contentcapture.ContentCaptureSession;
import androidx.compose.foundation.text.selection.U;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.platform.C0971v;
import androidx.lifecycle.p0;
import androidx.paging.V;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final /* synthetic */ class K extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ K(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        androidx.collection.J j;
        char c;
        long j2;
        long j3;
        androidx.collection.J j4;
        Object[] objArr;
        long[] jArr;
        androidx.collection.J j5;
        Object[] objArr2;
        long j6;
        long[] jArr2;
        androidx.compose.runtime.collection.b bVar;
        androidx.compose.runtime.collection.b bVar2;
        long[] jArr3;
        long j7;
        int i;
        androidx.compose.runtime.collection.b bVar3;
        Object[] objArr3;
        androidx.collection.J j8;
        Object[] objArr4;
        char c2;
        long j9;
        androidx.compose.runtime.collection.b bVar4;
        androidx.compose.runtime.collection.b bVar5;
        androidx.collection.J j10;
        Object[] objArr5;
        int i2;
        ContentCaptureSession contentCaptureSessionA;
        switch (this.a) {
            case 0:
                ((L) this.receiver).e();
                return Unit.a;
            case 1:
                ((L) this.receiver).e();
                return Unit.a;
            case 2:
                U u = (U) this.receiver;
                u.b();
                u.i();
                return Unit.a;
            case 3:
                ((U) this.receiver).k();
                return Unit.a;
            case 4:
                androidx.compose.ui.focus.f fVar = (androidx.compose.ui.focus.f) this.receiver;
                androidx.collection.J j11 = fVar.e;
                Object[] objArr6 = j11.b;
                long[] jArr4 = j11.a;
                int length = jArr4.length - 2;
                char c3 = 7;
                long j12 = -9187201950435737472L;
                androidx.collection.J j13 = fVar.c;
                if (length >= 0) {
                    int i3 = 0;
                    j3 = 255;
                    while (true) {
                        long j14 = jArr4[i3];
                        int i4 = i3;
                        if ((((~j14) << c3) & j14 & j12) != j12) {
                            int i5 = 8 - ((~(i4 - length)) >>> 31);
                            int i6 = 0;
                            while (i6 < i5) {
                                if ((j14 & 255) < 128) {
                                    c2 = c3;
                                    androidx.compose.ui.p pVar = (androidx.compose.ui.p) ((androidx.compose.ui.focus.n) objArr6[(i4 << 3) + i6]);
                                    j9 = j12;
                                    androidx.compose.ui.p pVarF = pVar.a;
                                    if (pVarF.m) {
                                        androidx.compose.runtime.collection.b bVar6 = null;
                                        while (pVarF != null) {
                                            if (pVarF instanceof androidx.compose.ui.focus.t) {
                                                j13.a((androidx.compose.ui.focus.t) pVarF);
                                            } else {
                                                if ((pVarF.c & 1024) != 0 && (pVarF instanceof AbstractC0918n)) {
                                                    androidx.compose.ui.p pVar2 = ((AbstractC0918n) pVarF).o;
                                                    j10 = j11;
                                                    int i7 = 0;
                                                    while (pVar2 != null) {
                                                        Object[] objArr7 = objArr6;
                                                        if ((pVar2.c & 1024) != 0) {
                                                            i7++;
                                                            if (i7 == 1) {
                                                                pVarF = pVar2;
                                                            } else {
                                                                if (bVar6 == null) {
                                                                    i2 = i7;
                                                                    bVar6 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                                } else {
                                                                    i2 = i7;
                                                                }
                                                                if (pVarF != null) {
                                                                    bVar6.b(pVarF);
                                                                    pVarF = null;
                                                                }
                                                                bVar6.b(pVar2);
                                                                i7 = i2;
                                                            }
                                                        }
                                                        pVar2 = pVar2.f;
                                                        objArr6 = objArr7;
                                                    }
                                                    objArr5 = objArr6;
                                                    if (i7 == 1) {
                                                    }
                                                    j11 = j10;
                                                    objArr6 = objArr5;
                                                }
                                                pVarF = AbstractC0910f.f(bVar6);
                                                j11 = j10;
                                                objArr6 = objArr5;
                                            }
                                            j10 = j11;
                                            objArr5 = objArr6;
                                            pVarF = AbstractC0910f.f(bVar6);
                                            j11 = j10;
                                            objArr6 = objArr5;
                                        }
                                        j8 = j11;
                                        objArr4 = objArr6;
                                        androidx.compose.ui.p pVar3 = pVar.a;
                                        if (!pVar3.m) {
                                            throw new IllegalStateException("visitChildren called on an unattached node");
                                        }
                                        androidx.compose.runtime.collection.b bVar7 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        androidx.compose.ui.p pVar4 = pVar3.f;
                                        if (pVar4 == null) {
                                            AbstractC0910f.b(bVar7, pVar3);
                                        } else {
                                            bVar7.b(pVar4);
                                        }
                                        while (bVar7.m()) {
                                            androidx.compose.ui.p pVarF2 = (androidx.compose.ui.p) bVar7.o(bVar7.c - 1);
                                            if ((pVarF2.d & 1024) == 0) {
                                                AbstractC0910f.b(bVar7, pVarF2);
                                            } else {
                                                while (true) {
                                                    if (pVarF2 == null) {
                                                        break;
                                                    }
                                                    if ((pVarF2.c & 1024) != 0) {
                                                        androidx.compose.runtime.collection.b bVar8 = null;
                                                        while (pVarF2 != null) {
                                                            if (pVarF2 instanceof androidx.compose.ui.focus.t) {
                                                                j13.a((androidx.compose.ui.focus.t) pVarF2);
                                                            } else {
                                                                if ((pVarF2.c & 1024) != 0 && (pVarF2 instanceof AbstractC0918n)) {
                                                                    androidx.compose.ui.p pVar5 = ((AbstractC0918n) pVarF2).o;
                                                                    int i8 = 0;
                                                                    while (pVar5 != null) {
                                                                        if ((pVar5.c & 1024) != 0) {
                                                                            i8++;
                                                                            if (i8 == 1) {
                                                                                bVar5 = bVar7;
                                                                                pVarF2 = pVar5;
                                                                            } else {
                                                                                if (bVar8 == null) {
                                                                                    bVar5 = bVar7;
                                                                                    bVar8 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                                                } else {
                                                                                    bVar5 = bVar7;
                                                                                }
                                                                                if (pVarF2 != null) {
                                                                                    bVar8.b(pVarF2);
                                                                                    pVarF2 = null;
                                                                                }
                                                                                bVar8.b(pVar5);
                                                                            }
                                                                        } else {
                                                                            bVar5 = bVar7;
                                                                        }
                                                                        pVar5 = pVar5.f;
                                                                        bVar7 = bVar5;
                                                                    }
                                                                    bVar4 = bVar7;
                                                                    if (i8 == 1) {
                                                                    }
                                                                    bVar7 = bVar4;
                                                                }
                                                                pVarF2 = AbstractC0910f.f(bVar8);
                                                                bVar7 = bVar4;
                                                            }
                                                            bVar4 = bVar7;
                                                            pVarF2 = AbstractC0910f.f(bVar8);
                                                            bVar7 = bVar4;
                                                        }
                                                    } else {
                                                        pVarF2 = pVarF2.f;
                                                        bVar7 = bVar7;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        j8 = j11;
                                        objArr4 = objArr6;
                                    }
                                } else {
                                    j8 = j11;
                                    objArr4 = objArr6;
                                    c2 = c3;
                                    j9 = j12;
                                }
                                j14 >>= 8;
                                i6++;
                                c3 = c2;
                                j12 = j9;
                                j11 = j8;
                                objArr6 = objArr4;
                            }
                            j = j11;
                            objArr3 = objArr6;
                            c = c3;
                            j2 = j12;
                            if (i5 == 8) {
                            }
                        } else {
                            j = j11;
                            objArr3 = objArr6;
                            c = c3;
                            j2 = j12;
                        }
                        if (i4 != length) {
                            i3 = i4 + 1;
                            c3 = c;
                            j12 = j2;
                            j11 = j;
                            objArr6 = objArr3;
                        }
                    }
                } else {
                    j = j11;
                    c = 7;
                    j2 = -9187201950435737472L;
                    j3 = 255;
                }
                j.b();
                androidx.collection.J j15 = fVar.d;
                Object[] objArr8 = j15.b;
                long[] jArr5 = j15.a;
                int length2 = jArr5.length - 2;
                androidx.collection.J j16 = fVar.f;
                if (length2 >= 0) {
                    int i9 = 0;
                    while (true) {
                        long j17 = jArr5[i9];
                        if ((((~j17) << c) & j17 & j2) != j2) {
                            int i10 = 8 - ((~(i9 - length2)) >>> 31);
                            int i11 = 0;
                            while (i11 < i10) {
                                if ((j17 & j3) < 128) {
                                    androidx.compose.ui.focus.d dVar = (androidx.compose.ui.focus.d) objArr8[(i9 << 3) + i11];
                                    androidx.compose.ui.p pVar6 = (androidx.compose.ui.p) dVar;
                                    j5 = j15;
                                    androidx.compose.ui.p pVar7 = pVar6.a;
                                    objArr2 = objArr8;
                                    boolean z = pVar7.m;
                                    androidx.compose.ui.focus.s sVar = androidx.compose.ui.focus.s.c;
                                    if (z) {
                                        androidx.compose.ui.focus.t tVar = null;
                                        androidx.compose.runtime.collection.b bVar9 = null;
                                        androidx.compose.ui.p pVarF3 = pVar7;
                                        boolean z2 = true;
                                        boolean z3 = false;
                                        while (pVarF3 != null) {
                                            androidx.compose.ui.focus.s sVar2 = sVar;
                                            if (pVarF3 instanceof androidx.compose.ui.focus.t) {
                                                androidx.compose.ui.focus.t tVar2 = (androidx.compose.ui.focus.t) pVarF3;
                                                if (tVar != null) {
                                                    z3 = true;
                                                }
                                                if (j13.c(tVar2)) {
                                                    j16.a(tVar2);
                                                    z2 = false;
                                                }
                                                tVar = tVar2;
                                            } else {
                                                if ((pVarF3.c & 1024) != 0 && (pVarF3 instanceof AbstractC0918n)) {
                                                    androidx.compose.ui.p pVar8 = ((AbstractC0918n) pVarF3).o;
                                                    jArr3 = jArr5;
                                                    int i12 = 0;
                                                    while (pVar8 != null) {
                                                        long j18 = j17;
                                                        if ((pVar8.c & 1024) != 0) {
                                                            i12++;
                                                            if (i12 == 1) {
                                                                pVarF3 = pVar8;
                                                            } else {
                                                                if (bVar9 == null) {
                                                                    i = i12;
                                                                    bVar3 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                                } else {
                                                                    i = i12;
                                                                    bVar3 = bVar9;
                                                                }
                                                                if (pVarF3 != null) {
                                                                    bVar3.b(pVarF3);
                                                                    pVarF3 = null;
                                                                }
                                                                bVar3.b(pVar8);
                                                                bVar9 = bVar3;
                                                                i12 = i;
                                                            }
                                                        }
                                                        pVar8 = pVar8.f;
                                                        j17 = j18;
                                                    }
                                                    j7 = j17;
                                                    if (i12 == 1) {
                                                    }
                                                    sVar = sVar2;
                                                    jArr5 = jArr3;
                                                    j17 = j7;
                                                }
                                                pVarF3 = AbstractC0910f.f(bVar9);
                                                sVar = sVar2;
                                                jArr5 = jArr3;
                                                j17 = j7;
                                            }
                                            jArr3 = jArr5;
                                            j7 = j17;
                                            pVarF3 = AbstractC0910f.f(bVar9);
                                            sVar = sVar2;
                                            jArr5 = jArr3;
                                            j17 = j7;
                                        }
                                        androidx.compose.ui.focus.s sVar3 = sVar;
                                        jArr2 = jArr5;
                                        j6 = j17;
                                        androidx.compose.ui.p pVar9 = pVar6.a;
                                        if (!pVar9.m) {
                                            throw new IllegalStateException("visitChildren called on an unattached node");
                                        }
                                        androidx.compose.runtime.collection.b bVar10 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                        androidx.compose.ui.p pVar10 = pVar9.f;
                                        if (pVar10 == null) {
                                            AbstractC0910f.b(bVar10, pVar9);
                                        } else {
                                            bVar10.b(pVar10);
                                        }
                                        while (bVar10.m()) {
                                            androidx.compose.ui.p pVarF4 = (androidx.compose.ui.p) bVar10.o(bVar10.c - 1);
                                            if ((pVarF4.d & 1024) == 0) {
                                                AbstractC0910f.b(bVar10, pVarF4);
                                            } else {
                                                while (pVarF4 != null) {
                                                    if ((pVarF4.c & 1024) != 0) {
                                                        androidx.compose.runtime.collection.b bVar11 = null;
                                                        while (pVarF4 != null) {
                                                            if (pVarF4 instanceof androidx.compose.ui.focus.t) {
                                                                androidx.compose.ui.focus.t tVar3 = (androidx.compose.ui.focus.t) pVarF4;
                                                                if (tVar != null) {
                                                                    z3 = true;
                                                                }
                                                                if (j13.c(tVar3)) {
                                                                    j16.a(tVar3);
                                                                    z2 = false;
                                                                }
                                                                tVar = tVar3;
                                                            } else {
                                                                if ((pVarF4.c & 1024) != 0 && (pVarF4 instanceof AbstractC0918n)) {
                                                                    androidx.compose.ui.p pVar11 = ((AbstractC0918n) pVarF4).o;
                                                                    int i13 = 0;
                                                                    while (pVar11 != null) {
                                                                        if ((pVar11.c & 1024) != 0) {
                                                                            i13++;
                                                                            if (i13 == 1) {
                                                                                bVar2 = bVar10;
                                                                                pVarF4 = pVar11;
                                                                            } else {
                                                                                if (bVar11 == null) {
                                                                                    bVar2 = bVar10;
                                                                                    bVar11 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                                                } else {
                                                                                    bVar2 = bVar10;
                                                                                }
                                                                                if (pVarF4 != null) {
                                                                                    bVar11.b(pVarF4);
                                                                                    pVarF4 = null;
                                                                                }
                                                                                bVar11.b(pVar11);
                                                                                pVar11 = pVar11.f;
                                                                                bVar10 = bVar2;
                                                                            }
                                                                        } else {
                                                                            bVar2 = bVar10;
                                                                        }
                                                                        pVar11 = pVar11.f;
                                                                        bVar10 = bVar2;
                                                                    }
                                                                    bVar = bVar10;
                                                                    if (i13 == 1) {
                                                                    }
                                                                    bVar10 = bVar;
                                                                }
                                                                pVarF4 = AbstractC0910f.f(bVar11);
                                                                bVar10 = bVar;
                                                            }
                                                            bVar = bVar10;
                                                            pVarF4 = AbstractC0910f.f(bVar11);
                                                            bVar10 = bVar;
                                                        }
                                                    } else {
                                                        pVarF4 = pVarF4.f;
                                                        bVar10 = bVar10;
                                                    }
                                                }
                                            }
                                            bVar10 = bVar10;
                                        }
                                        if (z2) {
                                            dVar.d0(z3 ? androidx.compose.ui.focus.a.q(dVar) : tVar != null ? tVar.N0() : sVar3);
                                        }
                                        j17 = j6 >> 8;
                                        i11++;
                                        j15 = j5;
                                        objArr8 = objArr2;
                                        jArr5 = jArr2;
                                    } else {
                                        dVar.d0(sVar);
                                    }
                                } else {
                                    j5 = j15;
                                    objArr2 = objArr8;
                                }
                                jArr2 = jArr5;
                                j6 = j17;
                                j17 = j6 >> 8;
                                i11++;
                                j15 = j5;
                                objArr8 = objArr2;
                                jArr5 = jArr2;
                            }
                            j4 = j15;
                            objArr = objArr8;
                            jArr = jArr5;
                            if (i10 == 8) {
                            }
                        } else {
                            j4 = j15;
                            objArr = objArr8;
                            jArr = jArr5;
                        }
                        if (i9 != length2) {
                            i9++;
                            j15 = j4;
                            objArr8 = objArr;
                            jArr5 = jArr;
                        }
                    }
                } else {
                    j4 = j15;
                }
                j4.b();
                Object[] objArr9 = j13.b;
                long[] jArr6 = j13.a;
                int length3 = jArr6.length - 2;
                if (length3 >= 0) {
                    int i14 = 0;
                    while (true) {
                        long j19 = jArr6[i14];
                        if ((((~j19) << c) & j19 & j2) != j2) {
                            int i15 = 8 - ((~(i14 - length3)) >>> 31);
                            for (int i16 = 0; i16 < i15; i16++) {
                                if ((j19 & j3) < 128) {
                                    androidx.compose.ui.focus.t tVar4 = (androidx.compose.ui.focus.t) objArr9[(i14 << 3) + i16];
                                    if (tVar4.m) {
                                        androidx.compose.ui.focus.s sVarN0 = tVar4.N0();
                                        tVar4.Q0();
                                        if (sVarN0 != tVar4.N0() || j16.c(tVar4)) {
                                            androidx.compose.ui.focus.a.E(tVar4);
                                        }
                                    }
                                }
                                j19 >>= 8;
                            }
                            if (i15 == 8) {
                            }
                        }
                        if (i14 != length3) {
                            i14++;
                        }
                    }
                }
                j13.b();
                j16.b();
                fVar.b.invoke();
                if (!j.g()) {
                    W4.f("Unprocessed FocusProperties nodes");
                    throw null;
                }
                if (!j4.g()) {
                    W4.f("Unprocessed FocusEvent nodes");
                    throw null;
                }
                if (j13.g()) {
                    return Unit.a;
                }
                W4.f("Unprocessed FocusTarget nodes");
                throw null;
            case 5:
                androidx.compose.ui.focus.j jVar = (androidx.compose.ui.focus.j) this.receiver;
                if (jVar.f.N0() == androidx.compose.ui.focus.s.c) {
                    jVar.c.invoke();
                }
                return Unit.a;
            case 6:
                View view = (View) this.receiver;
                int i17 = Build.VERSION.SDK_INT;
                if (i17 >= 30) {
                    androidx.compose.ui.platform.coreshims.g.a(view, 1);
                }
                if (i17 < 29 || (contentCaptureSessionA = androidx.compose.ui.platform.coreshims.f.a(view)) == null) {
                    return null;
                }
                return new androidx.compose.ui.platform.coreshims.d(contentCaptureSessionA, view);
            case 7:
                C0971v c0971v = (C0971v) this.receiver;
                if (c0971v.isFocused() || c0971v.hasFocus()) {
                    c0971v.clearFocus();
                }
                return Unit.a;
            case 8:
                return ((C0971v) this.receiver).u();
            case 9:
                ((V) this.receiver).c.k(Boolean.TRUE);
                return Unit.a;
            case 10:
                ((V) this.receiver).c.k(Boolean.FALSE);
                return Unit.a;
            case 11:
                ((V) this.receiver).c.k(Boolean.FALSE);
                return Unit.a;
            case 12:
                ((com.google.firebase.crashlytics.internal.concurrency.c) this.receiver).getClass();
                String threadName = Thread.currentThread().getName();
                Intrinsics.checkNotNullExpressionValue(threadName, "threadName");
                return Boolean.valueOf(StringsKt.G(threadName, "Firebase Background Thread #", false));
            case 13:
                ((com.google.firebase.crashlytics.internal.concurrency.c) this.receiver).getClass();
                String threadName2 = Thread.currentThread().getName();
                Intrinsics.checkNotNullExpressionValue(threadName2, "threadName");
                return Boolean.valueOf(StringsKt.G(threadName2, "Firebase Blocking Thread #", false));
            case 14:
                ((com.google.firebase.crashlytics.internal.concurrency.c) this.receiver).getClass();
                return Boolean.valueOf(!Looper.getMainLooper().isCurrentThread());
            case 15:
                ((com.quizlet.assembly.compose.modals.x) this.receiver).a();
                return Unit.a;
            case 16:
                ((L) this.receiver).c();
                return Unit.a;
            case 17:
                ((com.quizlet.assembly.compose.menu.s) this.receiver).b();
                return Unit.a;
            case 18:
                ((com.quizlet.explanations.questiondetail.viewmodel.f) this.receiver).C();
                return Unit.a;
            case 19:
                ((com.quizlet.explanations.questiondetail.viewmodel.f) this.receiver).C();
                return Unit.a;
            case 20:
                com.quizlet.explanations.solution.viewmodel.b bVar12 = (com.quizlet.explanations.solution.viewmodel.b) this.receiver;
                bVar12.l.put(Integer.valueOf(bVar12.k), Integer.valueOf(((List) bVar12.j.get(bVar12.k)).size()));
                bVar12.D(bVar12.k, true);
                ExplanationsLogger.EventData eventData = bVar12.B();
                ExplanationsLogger explanationsLogger = bVar12.c;
                explanationsLogger.getClass();
                Intrinsics.checkNotNullParameter(eventData, "eventData");
                ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
                com.quizlet.eventlogger.features.explanations.c cVar = new com.quizlet.eventlogger.features.explanations.c(explanationsLogger, eventData, 1);
                companion.getClass();
                explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_solution_show_all_steps_tapped", cVar));
                return Unit.a;
            case 21:
                ((com.quizlet.assembly.compose.menu.s) this.receiver).a();
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                ((com.quizlet.assembly.compose.menu.s) this.receiver).a();
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                ((L) this.receiver).c();
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                com.quizlet.features.blocks.g gVar = (com.quizlet.features.blocks.g) this.receiver;
                gVar.getClass();
                kotlinx.coroutines.E.A(p0.j(gVar), null, null, new com.quizlet.features.blocks.f(gVar, null), 3);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                com.quizlet.features.emailconfirmation.viewmodel.f fVar2 = (com.quizlet.features.emailconfirmation.viewmodel.f) ((com.quizlet.features.emailconfirmation.viewmodel.g) this.receiver);
                fVar2.e.a(com.quizlet.generated.enums.B.EMAIL_RESEND_CLICKED);
                kotlinx.coroutines.E.A(p0.j(fVar2), null, null, new com.quizlet.features.emailconfirmation.viewmodel.c(fVar2, null), 3);
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.quizlet.features.emailconfirmation.viewmodel.f fVar3 = (com.quizlet.features.emailconfirmation.viewmodel.f) ((com.quizlet.features.emailconfirmation.viewmodel.g) this.receiver);
                fVar3.e.a(com.quizlet.generated.enums.B.EMAIL_UPDATE_CLICKED);
                fVar3.g.h(com.quizlet.features.emailconfirmation.data.events.a.a);
                return Unit.a;
            case 27:
                ((com.quizlet.features.emailconfirmation.viewmodel.f) ((com.quizlet.features.emailconfirmation.viewmodel.g) this.receiver)).d.a(false);
                return Unit.a;
            case 28:
                com.quizlet.features.emailconfirmation.viewmodel.m mVar = (com.quizlet.features.emailconfirmation.viewmodel.m) ((com.quizlet.features.emailconfirmation.viewmodel.h) this.receiver);
                mVar.e.a(com.quizlet.generated.enums.B.EMAIL_RESEND_CLICKED);
                kotlinx.coroutines.E.A(p0.j(mVar), null, null, new com.quizlet.features.emailconfirmation.viewmodel.j(mVar, null), 3);
                return Unit.a;
            default:
                com.quizlet.features.emailconfirmation.viewmodel.m mVar2 = (com.quizlet.features.emailconfirmation.viewmodel.m) ((com.quizlet.features.emailconfirmation.viewmodel.h) this.receiver);
                mVar2.e.a(com.quizlet.generated.enums.B.LOGOUT_CLICKED);
                kotlinx.coroutines.E.A(p0.j(mVar2), null, null, new com.quizlet.features.emailconfirmation.viewmodel.i(mVar2, null), 3);
                return Unit.a;
        }
    }
}
