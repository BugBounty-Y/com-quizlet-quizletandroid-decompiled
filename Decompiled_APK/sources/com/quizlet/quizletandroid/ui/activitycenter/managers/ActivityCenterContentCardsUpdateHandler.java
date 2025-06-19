package com.quizlet.quizletandroid.ui.activitycenter.managers;

import android.os.Parcel;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.ui.contentcards.handlers.IContentCardsUpdateHandler;
import com.quizlet.login.common.navigation.d;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityCenterContentCardsUpdateHandler implements IContentCardsUpdateHandler {

    @NotNull
    public static final a CREATOR = new a();
    public d a;

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // com.braze.ui.contentcards.handlers.IContentCardsUpdateHandler
    public final List handleCardUpdate(ContentCardsUpdatedEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        d dVar = this.a;
        return dVar != null ? (List) dVar.invoke(event) : event.getAllCards();
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
    }
}
