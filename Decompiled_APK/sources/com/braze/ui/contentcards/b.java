package com.braze.ui.contentcards;

import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.braze.ui.contentcards.managers.BrazeContentCardsManager;
import com.braze.ui.feed.BrazeImageSwitcher;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ContentCardsFragment.onPause$lambda$4();
            case 1:
                return ContentCardsFragment.contentCardsUpdate$lambda$11();
            case 2:
                return ContentCardsFragment.contentCardsUpdate$lambda$12();
            case 3:
                return ContentCardsFragment.networkUnavailable$lambda$16();
            case 4:
                return ContentCardAdapter.markOnScreenCardsAsRead$lambda$4();
            case 5:
                return BrazeContentCardsManager.instance_delegate$lambda$0();
            case 6:
                return BrazeImageSwitcher._init_$lambda$0();
            case 7:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$18();
            case 8:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$24();
            case 9:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$34();
            case 10:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$25();
            case 11:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$26();
            case 12:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$27();
            case 13:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$28();
            case 14:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$29();
            case 15:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$30();
            case 16:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$31();
            case 17:
                return BrazeInAppMessageManager.unregisterInAppMessageManager$lambda$20();
            case 18:
                return BrazeInAppMessageManager.requestDisplayInAppMessage$lambda$32();
            case 19:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$47();
            case 20:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$48();
            case 21:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$38();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$39();
            case EventType.AUDIO /* 23 */:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$40();
            case EventType.VIDEO /* 24 */:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$41();
            case EventType.SUBS /* 25 */:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$42();
            case EventType.CDN /* 26 */:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$43();
            case 27:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$44();
            case 28:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$45();
            default:
                return BrazeInAppMessageManager.displayInAppMessage$lambda$46();
        }
    }
}
