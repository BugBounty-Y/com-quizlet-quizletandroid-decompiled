package com.braze.push;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.C0208f;
import com.braze.BrazeInternal;
import com.braze.C1481g;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.push.BrazePushReceiver;
import com.braze.support.BrazeLogger;
import com.braze.support.ReflectionUtils;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;
import java.lang.reflect.Method;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeFirebaseMessagingService extends FirebaseMessagingService {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$0(RemoteMessage remoteMessage) {
            return "Remote message did not originate from Braze. Not consuming remote message: " + remoteMessage;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$1(String str) {
            return AbstractC0147y.d("Fallback FCM service enabled. Attempting to use fallback class at ", str);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$2() {
            return "Fallback FCM service enabled but classpath is null. Not routing to any fallback service.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$3() {
            return "FallbackFirebaseMessagingService is not enabled";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$4(Map map) {
            return "Got remote message from FCM: " + map;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String handleBrazeRemoteMessage$lambda$5(String str, String str2) {
            return android.support.v4.media.session.a.m("Adding bundle item from FCM remote data with key: ", str, " and value: ", str2);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$10(String str) {
            return android.support.v4.media.session.a.B("Fallback firebase messaging service method ", str, ".onMessageReceived could not be retrieved. Not routing fallback RemoteMessage.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$11(String str) {
            return android.support.v4.media.session.a.B("Attempting to invoke firebase messaging fallback service ", str, ".onMessageReceived");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$6(String str) {
            return android.support.v4.media.session.a.B("Fallback firebase messaging service ", str, " could not be constructed. Not routing fallback RemoteMessage.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$7(String str) {
            return android.support.v4.media.session.a.B("Attempting to call ", str, " attachBaseContext");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$8(String str) {
            return android.support.v4.media.session.a.B("Failure invoking ", str, ".attachBaseContext. Not doing anything.");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String invokeFallbackFirebaseService$lambda$9() {
            return "Could not find attachBaseContext. Not doing anything.";
        }

        public final boolean handleBrazeRemoteMessage(@NotNull Context context, @NotNull RemoteMessage remoteMessage) throws SecurityException {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(remoteMessage, "remoteMessage");
            if (!isBrazePushNotification(remoteMessage)) {
                BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
                BrazeLogger.Priority priority = BrazeLogger.Priority.I;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new f(remoteMessage, 1), 6, (Object) null);
                BrazeConfigurationProvider configurationProvider = BrazeInternal.INSTANCE.getConfigurationProvider(context);
                if (!configurationProvider.isFallbackFirebaseMessagingServiceEnabled()) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(2), 7, (Object) null);
                    return false;
                }
                String fallbackFirebaseMessagingServiceClasspath = configurationProvider.getFallbackFirebaseMessagingServiceClasspath();
                if (fallbackFirebaseMessagingServiceClasspath == null) {
                    BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(1), 7, (Object) null);
                    return false;
                }
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new a(fallbackFirebaseMessagingServiceClasspath, 2), 6, (Object) null);
                invokeFallbackFirebaseService$android_sdk_ui_release(fallbackFirebaseMessagingServiceClasspath, remoteMessage, context);
                return false;
            }
            Map mapA = remoteMessage.a();
            Intrinsics.checkNotNullExpressionValue(mapA, "getData(...)");
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new f(mapA, 2), 6, (Object) null);
            Intent intent = new Intent("firebase_messaging_service_routing_action");
            Bundle bundle = new Bundle();
            for (Map.Entry entry : ((C0208f) mapA).entrySet()) {
                String str = (String) entry.getKey();
                String str2 = (String) entry.getValue();
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C1481g(19, str, str2), 6, (Object) null);
                bundle.putString(str, str2);
            }
            intent.putExtras(bundle);
            BrazePushReceiver.Companion.handleReceivedIntent$default(BrazePushReceiver.Companion, context, intent, false, 4, null);
            return true;
        }

        public final void invokeFallbackFirebaseService$android_sdk_ui_release(@NotNull String classpath, @NotNull RemoteMessage remoteMessage, @NotNull Context context) throws SecurityException {
            Intrinsics.checkNotNullParameter(classpath, "classpath");
            Intrinsics.checkNotNullParameter(remoteMessage, "remoteMessage");
            Intrinsics.checkNotNullParameter(context, "context");
            ReflectionUtils reflectionUtils = ReflectionUtils.INSTANCE;
            Object objConstructObjectQuietly$default = ReflectionUtils.constructObjectQuietly$default(reflectionUtils, classpath, null, null, 6, null);
            if (objConstructObjectQuietly$default == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(classpath, 3), 7, (Object) null);
                return;
            }
            Method declaredMethodQuietly = reflectionUtils.getDeclaredMethodQuietly(classpath, "attachBaseContext", Context.class);
            if (declaredMethodQuietly == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new k(3), 7, (Object) null);
                return;
            }
            declaredMethodQuietly.setAccessible(true);
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(classpath, 4), 7, (Object) null);
            if (!((Boolean) ReflectionUtils.invokeMethodQuietly(objConstructObjectQuietly$default, declaredMethodQuietly, context).a).booleanValue()) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(classpath, 5), 7, (Object) null);
                return;
            }
            Method methodQuietly = ReflectionUtils.getMethodQuietly(classpath, "onMessageReceived", (Class<?>[]) new Class[]{RemoteMessage.class});
            if (methodQuietly == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(classpath, 0), 7, (Object) null);
            } else {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(classpath, 1), 7, (Object) null);
                ((Boolean) ReflectionUtils.invokeMethodQuietly(objConstructObjectQuietly$default, methodQuietly, remoteMessage).a).getClass();
            }
        }

        public final boolean isBrazePushNotification(@NotNull RemoteMessage remoteMessage) {
            Intrinsics.checkNotNullParameter(remoteMessage, "remoteMessage");
            Map mapA = remoteMessage.a();
            Intrinsics.checkNotNullExpressionValue(mapA, "getData(...)");
            return "true".equals(((C0208f) mapA).get("_ab"));
        }

        private Companion() {
        }
    }
}
