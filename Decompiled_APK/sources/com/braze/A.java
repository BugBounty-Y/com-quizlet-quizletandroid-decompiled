package com.braze;

import android.os.Build;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class A implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ A(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.subscribeToContentCardsUpdates$lambda$110();
            case 1:
                return Braze.closeSession$lambda$43$lambda$42();
            case 2:
                return Braze.requestFeedRefresh$lambda$77();
            case 3:
                return Braze.openSession$lambda$40$lambda$39();
            case 4:
                return Braze.publishError$lambda$212();
            case 5:
                return Braze.subscribeToFeedUpdates$lambda$120();
            case 6:
                return Braze.lambda$27$lambda$4();
            case 7:
                String str = Build.MODEL;
                return Braze.lambda$2$lambda$1(Build.MODEL);
            case 8:
                return Braze.lambda$27$lambda$14();
            case 9:
                return Braze.lambda$27$lambda$15();
            case 10:
                return Braze.lambda$27$lambda$17();
            case 11:
                return Braze.lambda$27$lambda$18();
            case 12:
                return Braze.lambda$27$lambda$19();
            case 13:
                return Braze.lambda$27$lambda$20();
            case 14:
                return Braze.lambda$27$lambda$21();
            case 15:
                return Braze.lambda$27$lambda$22();
            case 16:
                return Braze.lambda$27$lambda$23();
            case 17:
                return Braze.lambda$27$lambda$24();
            case 18:
                return Braze._init_$lambda$3();
            case 19:
                return Braze.lambda$27$lambda$5();
            case 20:
                return Braze.lambda$27$lambda$25();
            case 21:
                return Braze.lambda$27$lambda$26();
            case EventType.WINDOW_STATE /* 22 */:
                return Braze.lambda$27$lambda$6();
            case EventType.AUDIO /* 23 */:
                return Braze.lambda$27$lambda$7();
            case EventType.VIDEO /* 24 */:
                return Braze.lambda$27$lambda$8();
            case EventType.SUBS /* 25 */:
                return Braze.lambda$27$lambda$9();
            case EventType.CDN /* 26 */:
                return Braze.lambda$27$lambda$10();
            case 27:
                return Braze.lambda$27$lambda$11();
            case 28:
                return Braze.lambda$27$lambda$12();
            default:
                return Braze.lambda$27$lambda$13();
        }
    }
}
