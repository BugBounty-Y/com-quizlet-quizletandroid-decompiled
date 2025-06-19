package com.skydoves.balloon;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Balloon b;

    public /* synthetic */ c(Balloon balloon, int i) {
        this.a = i;
        this.b = balloon;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Balloon.startBalloonHighlightAnimation$lambda$28(this.b);
                break;
            default:
                Balloon.startBalloonHighlightAnimation$lambda$28$lambda$27(this.b);
                break;
        }
    }
}
