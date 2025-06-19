package com.quizlet.quizletandroid.firebase.services;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.collection.C0208f;
import androidx.core.app.C1034v;
import com.appsflyer.AppsFlyerLib;
import com.braze.push.BrazeFirebaseMessagingService;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3689o4;
import com.google.firebase.messaging.RemoteMessage;
import com.google.firebase.messaging.p;
import com.quizlet.eventlogger.features.pushnotifications.FirebaseMessagePayload;
import com.quizlet.generated.enums.S1;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.RootActivity;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletFirebaseMessagingService extends a {
    public d d;
    public com.quizlet.data.repository.qclass.c e;

    public final void b(int i, RemoteMessage remoteMessage, FirebaseMessagePayload firebaseMessagePayload) {
        com.quizlet.data.repository.qclass.c cVar = this.e;
        if (cVar == null) {
            Intrinsics.m("notificationChannelsManager");
            throw null;
        }
        String channelId = firebaseMessagePayload.getChannel();
        Intrinsics.checkNotNullParameter(channelId, "channelId");
        List<NotificationChannel> notificationChannels = ((NotificationManager) cVar.c).getNotificationChannels();
        Intrinsics.checkNotNullExpressionValue(notificationChannels, "getNotificationChannels(...)");
        ArrayList arrayList = new ArrayList(C.q(notificationChannels, 10));
        Iterator<T> it2 = notificationChannels.iterator();
        while (it2.hasNext()) {
            arrayList.add(((NotificationChannel) it2.next()).getId());
        }
        C1034v c1034v = new C1034v(getApplicationContext(), arrayList.contains(channelId) ? firebaseMessagePayload.getChannel() : "miscellaneous_notification_channel");
        c1034v.y.icon = R.drawable.ic_notification_q;
        c1034v.q = getApplicationContext().getColor(R.color.assembly_twilight500);
        if (remoteMessage.c == null) {
            Bundle bundle = remoteMessage.a;
            if (p.z(bundle)) {
                remoteMessage.c = new androidx.work.impl.model.c(new p(bundle));
            }
        }
        androidx.work.impl.model.c cVar2 = remoteMessage.c;
        c1034v.e = C1034v.b(cVar2 != null ? (String) cVar2.b : null);
        if (remoteMessage.c == null) {
            Bundle bundle2 = remoteMessage.a;
            if (p.z(bundle2)) {
                remoteMessage.c = new androidx.work.impl.model.c(new p(bundle2));
            }
        }
        androidx.work.impl.model.c cVar3 = remoteMessage.c;
        c1034v.f = C1034v.b(cVar3 != null ? (String) cVar3.c : null);
        int i2 = RootActivity.o;
        Intrinsics.checkNotNullParameter(this, "context");
        Intrinsics.checkNotNullParameter(firebaseMessagePayload, "firebaseMessagePayload");
        Intent intent = new Intent(this, (Class<?>) RootActivity.class);
        intent.putExtra("firebasePayload", firebaseMessagePayload);
        intent.addFlags(268435456);
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 201326592);
        Intrinsics.checkNotNullExpressionValue(activity, "getActivity(...)");
        c1034v.g = activity;
        c1034v.c(16, true);
        Notification notificationA = c1034v.a();
        Context applicationContext = getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        Object systemService = applicationContext.getSystemService("notification");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
        ((NotificationManager) systemService).notify(i, notificationA);
    }

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public final void onMessageReceived(RemoteMessage remoteMessage) throws JSONException {
        String str;
        Intrinsics.checkNotNullParameter(remoteMessage, "remoteMessage");
        super.onMessageReceived(remoteMessage);
        Map data = remoteMessage.a();
        Intrinsics.checkNotNullExpressionValue(data, "getData(...)");
        Intrinsics.checkNotNullParameter(data, "data");
        if (((C0208f) data).containsKey("af-uinstall-tracking") || BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage(this, remoteMessage) || (str = (String) ((C0208f) remoteMessage.a()).get("data")) == null) {
            return;
        }
        FirebaseMessagePayload firebaseMessagePayloadH = AbstractC3689o4.h(str);
        d dVar = this.d;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        if (dVar.e.getPersonId() != firebaseMessagePayloadH.getUserId()) {
            return;
        }
        S1 type = firebaseMessagePayloadH.getType();
        int i = type == null ? -1 : b.a[type.ordinal()];
        if (i == 1) {
            Long setId = firebaseMessagePayloadH.getSetId();
            if (setId != null) {
                b((((int) (Math.abs(setId.longValue()) % 1048575)) << 8) | 33554433, remoteMessage, firebaseMessagePayloadH);
                return;
            }
            return;
        }
        if (i == 2) {
            Long setId2 = firebaseMessagePayloadH.getSetId();
            if (setId2 != null) {
                b((((int) (Math.abs(setId2.longValue()) % 1048575)) << 8) | 50331649, remoteMessage, firebaseMessagePayloadH);
                return;
            }
            return;
        }
        if (i != 3) {
            if (i == 4 && firebaseMessagePayloadH.getDestination() != null) {
                b(firebaseMessagePayloadH.getMessageId().hashCode(), remoteMessage, firebaseMessagePayloadH);
                return;
            }
            return;
        }
        Long folderId = firebaseMessagePayloadH.getFolderId();
        if (folderId != null) {
            b((((int) (Math.abs(folderId.longValue()) % 1048575)) << 8) | 33554434, remoteMessage, firebaseMessagePayloadH);
        }
    }

    @Override // com.google.firebase.messaging.FirebaseMessagingService
    public final void onNewToken(String newToken) {
        Intrinsics.checkNotNullParameter(newToken, "token");
        super.onNewToken(newToken);
        Context context = getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(context, "getApplicationContext(...)");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(newToken, "newToken");
        AppsFlyerLib.getInstance().updateServerUninstallToken(context, newToken);
    }
}
