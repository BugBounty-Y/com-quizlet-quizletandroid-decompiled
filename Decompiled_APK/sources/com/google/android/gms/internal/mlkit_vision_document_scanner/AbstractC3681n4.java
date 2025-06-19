package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.graphics.Color;
import androidx.appcompat.widget.SwitchCompat;
import com.amazon.device.ads.DtbConstants;
import com.braze.models.cards.Card;
import com.braze.models.cards.ShortNewsCard;
import com.braze.models.cards.TextAnnouncementCard;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.n4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3681n4 {
    public static final void a(SwitchCompat switchCompat, String str, String str2) {
        Intrinsics.checkNotNullParameter(switchCompat, "<this>");
        if (str == null || str.length() == 0) {
            switchCompat.getTrackDrawable().setTint(switchCompat.getContext().getColor(R.color.light_greyOT));
        } else {
            switchCompat.getTrackDrawable().setTint(Color.parseColor(str));
        }
        if (str2 == null || str2.length() == 0) {
            switchCompat.getThumbDrawable().setTint(switchCompat.getContext().getColor(R.color.contentTextColorOT));
        } else {
            switchCompat.getThumbDrawable().setTint(Color.parseColor(str2));
        }
    }

    public static final ArrayList b(List list) {
        String str;
        ArrayList arrayListM = assistantMode.refactored.a.m("<this>", list);
        for (Object obj : list) {
            Card card = (Card) obj;
            boolean zB = Intrinsics.b(card.getExtras().get("feedType"), "LIHP");
            boolean z = ((card instanceof TextAnnouncementCard) || (card instanceof ShortNewsCard)) && ((str = card.getExtras().get("platform")) == null || StringsKt.O(str) || StringsKt.G(str, DtbConstants.NATIVE_OS_NAME, true)) && !zB;
            if (!z && !zB) {
                card.setViewed(true);
                card.setDismissed(true);
            }
            if (z) {
                arrayListM.add(obj);
            }
        }
        return arrayListM;
    }
}
