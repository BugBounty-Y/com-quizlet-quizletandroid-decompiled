package org.prebid.mobile.rendering.models;

/* loaded from: classes3.dex */
public enum AdPosition {
    UNDEFINED(-1),
    /* JADX INFO: Fake field, exist only in values array */
    UNKNOWN(0),
    /* JADX INFO: Fake field, exist only in values array */
    ABOVE_THE_FOLD(1),
    /* JADX INFO: Fake field, exist only in values array */
    LOCKED(2),
    /* JADX INFO: Fake field, exist only in values array */
    BELOW_THE_FOLD(3),
    /* JADX INFO: Fake field, exist only in values array */
    HEADER(4),
    /* JADX INFO: Fake field, exist only in values array */
    FOOTER(5),
    /* JADX INFO: Fake field, exist only in values array */
    SIDEBAR(6),
    /* JADX INFO: Fake field, exist only in values array */
    FULLSCREEN(7);

    public final int a;

    AdPosition(int i) {
        this.a = i;
    }
}
