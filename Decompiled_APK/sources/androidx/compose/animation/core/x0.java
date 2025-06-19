package androidx.compose.animation.core;

/* loaded from: classes.dex */
public interface x0 {
    Object a();

    default boolean b(Object obj, Object obj2) {
        return obj.equals(a()) && obj2.equals(c());
    }

    Object c();
}
