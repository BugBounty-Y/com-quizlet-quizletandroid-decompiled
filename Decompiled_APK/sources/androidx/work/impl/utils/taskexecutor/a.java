package androidx.work.impl.utils.taskexecutor;

/* loaded from: classes.dex */
public interface a {
    default void a(Runnable runnable) {
        ((c) this).a.execute(runnable);
    }
}
