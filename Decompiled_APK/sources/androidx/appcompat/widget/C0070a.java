package androidx.appcompat.widget;

import androidx.core.view.InterfaceC1045e0;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.AbstractC4907a;
import kotlin.C4909c;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.JsonNull;

/* renamed from: androidx.appcompat.widget.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0070a implements InterfaceC1045e0 {
    public int a;
    public boolean b;
    public Object c;

    public C0070a(MessageDigest messageDigest, int i) {
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        this.c = messageDigest;
        this.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b8  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(androidx.appcompat.widget.C0070a r10, kotlin.AbstractC4908b r11, kotlin.coroutines.jvm.internal.a r12) {
        /*
            Method dump skipped, instructions count: 204
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C0070a.d(androidx.appcompat.widget.a, kotlin.b, kotlin.coroutines.jvm.internal.a):java.lang.Object");
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public void a() {
        this.b = true;
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public void b() {
        super/*android.view.View*/.setVisibility(0);
        this.b = false;
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public void c() {
        if (this.b) {
            return;
        }
        ActionBarContextView actionBarContextView = (ActionBarContextView) this.c;
        actionBarContextView.f = null;
        super/*android.view.View*/.setVisibility(this.a);
    }

    public kotlinx.serialization.json.k e() {
        kotlinx.serialization.json.k vVar;
        Object obj;
        Object objInvoke;
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) this.c;
        byte bJ = aVar.J();
        if (bJ == 1) {
            return g(true);
        }
        if (bJ == 0) {
            return g(false);
        }
        if (bJ != 6) {
            if (bJ == 8) {
                return f();
            }
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "Cannot read Json element because of unexpected ".concat(kotlinx.serialization.json.internal.k.u(bJ)), 0, null, 6);
            throw null;
        }
        int i = this.a + 1;
        this.a = i;
        if (i == 200) {
            kotlinx.serialization.json.internal.s block = new kotlinx.serialization.json.internal.s(this, null);
            com.quizlet.quizletandroid.managers.upgrade.a aVar2 = new com.quizlet.quizletandroid.managers.upgrade.a(block);
            Unit unit = Unit.a;
            kotlin.coroutines.intrinsics.a aVar3 = AbstractC4907a.a;
            Intrinsics.checkNotNullParameter(aVar2, "<this>");
            Intrinsics.checkNotNullParameter(block, "block");
            C4909c c4909c = new C4909c(null);
            c4909c.a = block;
            c4909c.b = unit;
            c4909c.c = c4909c;
            kotlin.coroutines.intrinsics.a aVar4 = AbstractC4907a.a;
            c4909c.d = aVar4;
            while (true) {
                obj = c4909c.d;
                kotlin.coroutines.h completion = c4909c.c;
                if (completion == null) {
                    break;
                }
                kotlin.p pVar = kotlin.r.b;
                if (Intrinsics.b(aVar4, obj)) {
                    try {
                        kotlinx.serialization.json.internal.s sVar = c4909c.a;
                        Unit unit2 = c4909c.b;
                        if (sVar == null) {
                            Intrinsics.checkNotNullParameter(sVar, "<this>");
                            Intrinsics.checkNotNullParameter(completion, "completion");
                            Intrinsics.checkNotNullParameter(completion, "completion");
                            CoroutineContext context = completion.getContext();
                            Object fVar = context == kotlin.coroutines.n.a ? new kotlin.coroutines.intrinsics.f(completion) : new kotlin.coroutines.intrinsics.g(completion, context);
                            kotlin.jvm.internal.O.d(3, sVar);
                            objInvoke = sVar.invoke(c4909c, unit2, fVar);
                        } else {
                            kotlin.jvm.internal.O.d(3, sVar);
                            objInvoke = sVar.invoke(c4909c, unit2, completion);
                        }
                        if (objInvoke != kotlin.coroutines.intrinsics.a.a) {
                            completion.resumeWith(objInvoke);
                        }
                    } catch (Throwable th) {
                        kotlin.p pVar2 = kotlin.r.b;
                        completion.resumeWith(androidx.glance.appwidget.protobuf.Z.b(th));
                    }
                } else {
                    c4909c.d = aVar4;
                    completion.resumeWith(obj);
                }
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            vVar = (kotlinx.serialization.json.k) obj;
        } else {
            byte bI = aVar.i((byte) 6);
            if (aVar.J() == 4) {
                androidx.camera.camera2.internal.concurrent.a.r(aVar, "Unexpected leading comma", 0, null, 6);
                throw null;
            }
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            while (true) {
                if (!aVar.e()) {
                    break;
                }
                String strM = this.b ? aVar.m() : aVar.l();
                aVar.i((byte) 5);
                linkedHashMap.put(strM, e());
                bI = aVar.h();
                if (bI != 4) {
                    if (bI != 7) {
                        androidx.camera.camera2.internal.concurrent.a.r(aVar, "Expected end of the object or comma", 0, null, 6);
                        throw null;
                    }
                }
            }
            if (bI == 6) {
                aVar.i((byte) 7);
            } else if (bI == 4) {
                kotlinx.serialization.json.internal.k.o(aVar, "object");
                throw null;
            }
            vVar = new kotlinx.serialization.json.v(linkedHashMap);
        }
        this.a--;
        return vVar;
    }

    public kotlinx.serialization.json.d f() {
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) this.c;
        byte bH = aVar.h();
        if (aVar.J() == 4) {
            androidx.camera.camera2.internal.concurrent.a.r(aVar, "Unexpected leading comma", 0, null, 6);
            throw null;
        }
        ArrayList arrayList = new ArrayList();
        while (aVar.e()) {
            arrayList.add(e());
            bH = aVar.h();
            if (bH != 4) {
                boolean z = bH == 9;
                int i = aVar.b;
                if (!z) {
                    androidx.camera.camera2.internal.concurrent.a.r(aVar, "Expected end of the array or comma", i, null, 4);
                    throw null;
                }
            }
        }
        if (bH == 8) {
            aVar.i((byte) 9);
        } else if (bH == 4) {
            kotlinx.serialization.json.internal.k.o(aVar, "array");
            throw null;
        }
        return new kotlinx.serialization.json.d(arrayList);
    }

    public kotlinx.serialization.json.y g(boolean z) {
        androidx.camera.camera2.internal.concurrent.a aVar = (androidx.camera.camera2.internal.concurrent.a) this.c;
        String strM = (this.b || !z) ? aVar.m() : aVar.l();
        return (z || !Intrinsics.b(strM, "null")) ? new kotlinx.serialization.json.r(strM, z, null) : JsonNull.INSTANCE;
    }
}
