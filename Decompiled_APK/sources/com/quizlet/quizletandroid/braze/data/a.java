package com.quizlet.quizletandroid.braze.data;

import com.braze.Braze;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.events.IEventSubscriber;
import com.braze.models.cards.Card;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3681n4;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.interactor.achievements.f;
import com.quizlet.data.model.C4184z;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements IEventSubscriber {
    public static final long f = TimeUnit.MINUTES.toMillis(30);
    public final Braze a;
    public final f b;
    public final C4184z c;
    public long d;
    public r e;

    public a(Braze braze, f syncedActivityCenterManager, C4184z buildConfigModel) {
        Intrinsics.checkNotNullParameter(braze, "braze");
        Intrinsics.checkNotNullParameter(syncedActivityCenterManager, "syncedActivityCenterManager");
        Intrinsics.checkNotNullParameter(buildConfigModel, "buildConfigModel");
        this.a = braze;
        this.b = syncedActivityCenterManager;
        this.c = buildConfigModel;
        this.e = Z.f("create(...)");
    }

    public final int a(List list) {
        ArrayList arrayListB = AbstractC3681n4.b(list);
        this.b.n(arrayListB);
        int i = 0;
        if (arrayListB.isEmpty()) {
            return 0;
        }
        Iterator it2 = arrayListB.iterator();
        while (it2.hasNext()) {
            if (!((Card) it2.next()).getViewed() && (i = i + 1) < 0) {
                B.o();
                throw null;
            }
        }
        return i;
    }

    @Override // com.braze.events.IEventSubscriber
    public final void trigger(Object obj) {
        ContentCardsUpdatedEvent message = (ContentCardsUpdatedEvent) obj;
        Intrinsics.checkNotNullParameter(message, "message");
        this.d = System.currentTimeMillis();
        this.e.onSuccess(Integer.valueOf(a(message.getAllCards())));
    }
}
