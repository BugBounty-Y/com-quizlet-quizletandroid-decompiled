package androidx.compose.animation.core;

/* loaded from: classes.dex */
public interface N0 {
    boolean a();

    long b(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3);

    AbstractC0267t j(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3);

    default AbstractC0267t n(AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3) {
        return j(b(abstractC0267t, abstractC0267t2, abstractC0267t3), abstractC0267t, abstractC0267t2, abstractC0267t3);
    }

    AbstractC0267t t(long j, AbstractC0267t abstractC0267t, AbstractC0267t abstractC0267t2, AbstractC0267t abstractC0267t3);
}
