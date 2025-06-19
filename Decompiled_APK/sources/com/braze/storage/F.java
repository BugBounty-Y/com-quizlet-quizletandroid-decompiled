package com.braze.storage;

import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeImageUtils;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.IntentUtils;
import com.braze.support.JsonUtils;
import com.braze.support.PermissionUtils;
import com.braze.support.ReflectionUtils;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class F implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ F(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return v.a();
            case 1:
                return v.b();
            case 2:
                return v.d();
            case 3:
                return y.b();
            case 4:
                return BrazeFileUtils.isRemoteUri$lambda$3();
            case 5:
                return BrazeFileUtils.downloadFileToPath$lambda$7();
            case 6:
                return BrazeFileUtils.downloadFileToPath$lambda$6();
            case 7:
                return BrazeFileUtils.downloadFileToPath$lambda$5();
            case 8:
                return BrazeImageUtils.resizeToBitmapDimensions$lambda$0();
            case 9:
                return BrazeImageUtils.getLocalBitmap$lambda$14();
            case 10:
                return BrazeImageUtils.getLocalBitmap$lambda$11();
            case 11:
                return BrazeImageUtils.getRemoteBitmap$lambda$22();
            case 12:
                return BrazeImageUtils.calculateInSampleSize$lambda$4();
            case 13:
                return BrazeImageUtils.getLocalBitmap$lambda$16();
            case 14:
                return BrazeLogger.checkForSystemLogLevelProperty$lambda$1();
            case 15:
                return DateTimeUtils.nowInMilliseconds$lambda$1();
            case 16:
                return com.braze.configuration.g.m();
            case 17:
                return IntentUtils.random_delegate$lambda$0();
            case 18:
                return JsonUtils.getPrettyPrintedString$lambda$6();
            case 19:
                return JsonUtils.parseJsonObjectIntoBundle$lambda$10();
            case 20:
                return JsonUtils.getColorIntegerOrNull$lambda$8();
            case 21:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$5();
            case EventType.WINDOW_STATE /* 22 */:
                return PermissionUtils.requestPushPermissionPrompt$lambda$3();
            case EventType.AUDIO /* 23 */:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$6();
            case EventType.VIDEO /* 24 */:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$8();
            case EventType.SUBS /* 25 */:
                return PermissionUtils.wouldPushPermissionPromptDisplay$lambda$10();
            case EventType.CDN /* 26 */:
                return PermissionUtils.requestPushPermissionPrompt$lambda$1();
            case 27:
                return PermissionUtils.requestPushPermissionPrompt$lambda$2();
            case 28:
                return PermissionUtils.requestPushPermissionPrompt$lambda$4();
            default:
                return ReflectionUtils.invokeMethodQuietly$lambda$5();
        }
    }
}
