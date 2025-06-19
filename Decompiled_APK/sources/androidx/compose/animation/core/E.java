package androidx.compose.animation.core;

/* loaded from: classes.dex */
public interface E extends InterfaceC0256n {
    @Override // androidx.compose.animation.core.InterfaceC0256n
    default N0 a(L0 l0) {
        return new com.quizlet.data.interactor.progress.c(this);
    }

    float b(long j, float f, float f2, float f3);

    long c(float f, float f2, float f3);

    default float d(float f, float f2, float f3) {
        return b(c(f, f2, f3), f, f2, f3);
    }

    float e(long j, float f, float f2, float f3);
}
