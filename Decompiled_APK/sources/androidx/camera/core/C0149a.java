package androidx.camera.core;

import android.graphics.Matrix;
import android.media.Image;
import androidx.camera.core.impl.v0;

/* renamed from: androidx.camera.core.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0149a implements O {
    public final Image a;
    public final com.quizlet.data.repository.school.membership.a[] b;
    public final C0154f c;

    public C0149a(Image image) {
        this.a = image;
        Image.Plane[] planes = image.getPlanes();
        if (planes != null) {
            this.b = new com.quizlet.data.repository.school.membership.a[planes.length];
            for (int i = 0; i < planes.length; i++) {
                this.b[i] = new com.quizlet.data.repository.school.membership.a(planes[i], 5);
            }
        } else {
            this.b = new com.quizlet.data.repository.school.membership.a[0];
        }
        this.c = new C0154f(v0.b, image.getTimestamp(), 0, new Matrix());
    }

    @Override // androidx.camera.core.O
    public final M N() {
        return this.c;
    }

    @Override // androidx.camera.core.O
    public final Image T() {
        return this.a;
    }

    @Override // androidx.camera.core.O
    public final int b() {
        return this.a.getHeight();
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }

    @Override // androidx.camera.core.O
    public final int getWidth() {
        return this.a.getWidth();
    }

    @Override // androidx.camera.core.O
    public final int m() {
        return this.a.getFormat();
    }

    @Override // androidx.camera.core.O
    public final com.quizlet.data.repository.school.membership.a[] o() {
        return this.b;
    }
}
