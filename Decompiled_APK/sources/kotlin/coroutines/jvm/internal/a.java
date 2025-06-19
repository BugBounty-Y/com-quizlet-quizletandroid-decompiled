package kotlin.coroutines.jvm.internal;

import androidx.glance.appwidget.protobuf.Z;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class a implements kotlin.coroutines.h, d, Serializable {
    private final kotlin.coroutines.h<Object> completion;

    public a(kotlin.coroutines.h hVar) {
        this.completion = hVar;
    }

    @NotNull
    public kotlin.coroutines.h<Unit> create(@NotNull kotlin.coroutines.h<?> completion) {
        Intrinsics.checkNotNullParameter(completion, "completion");
        throw new UnsupportedOperationException("create(Continuation) has not been overridden");
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public d getCallerFrame() {
        kotlin.coroutines.h<Object> hVar = this.completion;
        if (hVar instanceof d) {
            return (d) hVar;
        }
        return null;
    }

    public final kotlin.coroutines.h<Object> getCompletion() {
        return this.completion;
    }

    public StackTraceElement getStackTraceElement() throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException {
        int iIntValue;
        String strC;
        Intrinsics.checkNotNullParameter(this, "<this>");
        e eVar = (e) getClass().getAnnotation(e.class);
        String str = null;
        if (eVar == null) {
            return null;
        }
        int iV = eVar.v();
        if (iV > 1) {
            throw new IllegalStateException(("Debug metadata version mismatch. Expected: 1, got " + iV + ". Please update the Kotlin standard library.").toString());
        }
        try {
            Field declaredField = getClass().getDeclaredField("label");
            declaredField.setAccessible(true);
            Object obj = declaredField.get(this);
            Integer num = obj instanceof Integer ? (Integer) obj : null;
            iIntValue = (num != null ? num.intValue() : 0) - 1;
        } catch (Exception unused) {
            iIntValue = -1;
        }
        int i = iIntValue >= 0 ? eVar.l()[iIntValue] : -1;
        f.a.getClass();
        Intrinsics.checkNotNullParameter(this, "continuation");
        com.google.android.gms.internal.appset.e eVar2 = f.c;
        com.google.android.gms.internal.appset.e eVar3 = f.b;
        if (eVar2 == null) {
            try {
                com.google.android.gms.internal.appset.e eVar4 = new com.google.android.gms.internal.appset.e(Class.class.getDeclaredMethod("getModule", null), getClass().getClassLoader().loadClass("java.lang.Module").getDeclaredMethod("getDescriptor", null), getClass().getClassLoader().loadClass("java.lang.module.ModuleDescriptor").getDeclaredMethod("name", null), 19);
                f.c = eVar4;
                eVar2 = eVar4;
            } catch (Exception unused2) {
                f.c = eVar3;
                eVar2 = eVar3;
            }
        }
        if (eVar2 != eVar3) {
            Method method = (Method) eVar2.b;
            Object objInvoke = method != null ? method.invoke(getClass(), null) : null;
            if (objInvoke != null) {
                Method method2 = (Method) eVar2.c;
                Object objInvoke2 = method2 != null ? method2.invoke(objInvoke, null) : null;
                if (objInvoke2 != null) {
                    Method method3 = (Method) eVar2.d;
                    Object objInvoke3 = method3 != null ? method3.invoke(objInvoke2, null) : null;
                    if (objInvoke3 instanceof String) {
                        str = (String) objInvoke3;
                    }
                }
            }
        }
        if (str == null) {
            strC = eVar.c();
        } else {
            strC = str + '/' + eVar.c();
        }
        return new StackTraceElement(strC, eVar.m(), eVar.f(), i);
    }

    public abstract Object invokeSuspend(Object obj);

    public void releaseIntercepted() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.coroutines.h
    public final void resumeWith(@NotNull Object obj) {
        kotlin.coroutines.h frame = this;
        while (true) {
            Intrinsics.checkNotNullParameter(frame, "frame");
            a aVar = (a) frame;
            kotlin.coroutines.h hVar = aVar.completion;
            Intrinsics.d(hVar);
            try {
                obj = aVar.invokeSuspend(obj);
            } catch (Throwable th) {
                p pVar = r.b;
                obj = Z.b(th);
            }
            if (obj == kotlin.coroutines.intrinsics.a.a) {
                return;
            }
            p pVar2 = r.b;
            aVar.releaseIntercepted();
            if (!(hVar instanceof a)) {
                hVar.resumeWith(obj);
                return;
            }
            frame = hVar;
        }
    }

    @NotNull
    public String toString() throws IllegalAccessException, NoSuchFieldException, SecurityException, IllegalArgumentException {
        StringBuilder sb = new StringBuilder("Continuation at ");
        Object stackTraceElement = getStackTraceElement();
        if (stackTraceElement == null) {
            stackTraceElement = getClass().getName();
        }
        sb.append(stackTraceElement);
        return sb.toString();
    }

    @NotNull
    public kotlin.coroutines.h<Unit> create(Object obj, @NotNull kotlin.coroutines.h<?> completion) {
        Intrinsics.checkNotNullParameter(completion, "completion");
        throw new UnsupportedOperationException("create(Any?;Continuation) has not been overridden");
    }
}
