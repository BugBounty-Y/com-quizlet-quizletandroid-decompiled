package com.google.android.material.carousel;

/* loaded from: classes2.dex */
public final class b extends androidx.sqlite.db.b {
    public final /* synthetic */ int c;
    public final /* synthetic */ CarouselLayoutManager d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(CarouselLayoutManager carouselLayoutManager, int i) {
        super(1, 3);
        this.c = i;
        switch (i) {
            case 1:
                this.d = carouselLayoutManager;
                super(0, 3);
                break;
            default:
                this.d = carouselLayoutManager;
                break;
        }
    }

    @Override // androidx.sqlite.db.b
    public final int b() {
        switch (this.c) {
            case 0:
                return this.d.o;
            default:
                CarouselLayoutManager carouselLayoutManager = this.d;
                return carouselLayoutManager.o - carouselLayoutManager.G();
        }
    }

    @Override // androidx.sqlite.db.b
    public final int c() {
        switch (this.c) {
            case 0:
                return this.d.H();
            default:
                return 0;
        }
    }

    @Override // androidx.sqlite.db.b
    public final int d() {
        switch (this.c) {
            case 0:
                CarouselLayoutManager carouselLayoutManager = this.d;
                return carouselLayoutManager.n - carouselLayoutManager.I();
            default:
                return this.d.n;
        }
    }

    @Override // androidx.sqlite.db.b
    public final int e() {
        switch (this.c) {
            case 0:
                return 0;
            default:
                CarouselLayoutManager carouselLayoutManager = this.d;
                if (carouselLayoutManager.J0()) {
                    return carouselLayoutManager.n;
                }
                return 0;
        }
    }

    @Override // androidx.sqlite.db.b
    public final int f() {
        switch (this.c) {
            case 0:
                return 0;
            default:
                return this.d.J();
        }
    }
}
