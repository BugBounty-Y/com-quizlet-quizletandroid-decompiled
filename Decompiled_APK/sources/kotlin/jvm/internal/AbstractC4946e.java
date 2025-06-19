package kotlin.jvm.internal;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.util.List;
import java.util.Map;

/* renamed from: kotlin.jvm.internal.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4946e implements kotlin.reflect.b, Serializable {
    public static final Object NO_RECEIVER = C4945d.a;
    private final boolean isTopLevel;
    private final String name;
    private final Class owner;
    protected final Object receiver;
    private transient kotlin.reflect.b reflected;
    private final String signature;

    public AbstractC4946e() {
        this(NO_RECEIVER, null, null, null, false);
    }

    @Override // kotlin.reflect.b
    public Object call(Object... objArr) {
        return getReflected().call(objArr);
    }

    @Override // kotlin.reflect.b
    public Object callBy(Map map) {
        return getReflected().callBy(map);
    }

    public kotlin.reflect.b compute() {
        kotlin.reflect.b bVar = this.reflected;
        if (bVar != null) {
            return bVar;
        }
        kotlin.reflect.b bVarComputeReflected = computeReflected();
        this.reflected = bVarComputeReflected;
        return bVarComputeReflected;
    }

    public abstract kotlin.reflect.b computeReflected();

    @Override // kotlin.reflect.a
    public List<Annotation> getAnnotations() {
        return getReflected().getAnnotations();
    }

    public Object getBoundReceiver() {
        return this.receiver;
    }

    @Override // kotlin.reflect.b
    public String getName() {
        return this.name;
    }

    public kotlin.reflect.e getOwner() {
        Class cls = this.owner;
        if (cls == null) {
            return null;
        }
        if (!this.isTopLevel) {
            return K.a(cls);
        }
        K.a.getClass();
        return new x(cls);
    }

    @Override // kotlin.reflect.b
    public List<Object> getParameters() {
        return getReflected().getParameters();
    }

    public kotlin.reflect.b getReflected() {
        kotlin.reflect.b bVarCompute = compute();
        if (bVarCompute != this) {
            return bVarCompute;
        }
        throw new kotlin.jvm.b();
    }

    @Override // kotlin.reflect.b
    public kotlin.reflect.o getReturnType() {
        return getReflected().getReturnType();
    }

    public String getSignature() {
        return this.signature;
    }

    @Override // kotlin.reflect.b
    public List<kotlin.reflect.p> getTypeParameters() {
        return getReflected().getTypeParameters();
    }

    @Override // kotlin.reflect.b
    public kotlin.reflect.t getVisibility() {
        return getReflected().getVisibility();
    }

    @Override // kotlin.reflect.b
    public boolean isAbstract() {
        return getReflected().isAbstract();
    }

    @Override // kotlin.reflect.b
    public boolean isFinal() {
        return getReflected().isFinal();
    }

    @Override // kotlin.reflect.b
    public boolean isOpen() {
        return getReflected().isOpen();
    }

    @Override // kotlin.reflect.b
    public boolean isSuspend() {
        return getReflected().isSuspend();
    }

    public AbstractC4946e(Object obj, Class cls, String str, String str2, boolean z) {
        this.receiver = obj;
        this.owner = cls;
        this.name = str;
        this.signature = str2;
        this.isTopLevel = z;
    }
}
