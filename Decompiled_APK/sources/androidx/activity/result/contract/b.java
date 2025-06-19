package androidx.activity.result.contract;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.ActivityInfo;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ext.SdkExtensions;
import android.provider.MediaStore;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.IntentSenderRequest;
import androidx.activity.result.j;
import androidx.fragment.app.AbstractC1136h0;
import androidx.webkit.internal.p;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends a {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // androidx.activity.result.contract.a
    public final Intent a(Context context, Object obj) {
        Bundle bundleExtra;
        switch (this.a) {
            case 0:
                j input = (j) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input, "input");
                int i = Build.VERSION.SDK_INT;
                if (i >= 33 || (i >= 30 && SdkExtensions.getExtensionVersion(30) >= 2)) {
                    Intent intent = new Intent("android.provider.action.PICK_IMAGES");
                    intent.setType(com.bumptech.glide.b.b(input.a));
                    int iMin = Math.min(5, input.b);
                    if (iMin <= 1 || iMin > MediaStore.getPickImagesMaxLimit()) {
                        throw new IllegalArgumentException("Max items must be greater than 1 and lesser than or equal to MediaStore.getPickImagesMaxLimit()");
                    }
                    intent.putExtra("android.provider.extra.PICK_IMAGES_MAX", iMin);
                    input.c.getClass();
                    intent.putExtra("android.provider.extra.PICK_IMAGES_LAUNCH_TAB", 1);
                    intent.putExtra("android.provider.extra.PICK_IMAGES_IN_ORDER", false);
                    return intent;
                }
                Intrinsics.checkNotNullParameter(context, "context");
                if (com.bumptech.glide.b.a(context) == null) {
                    Intent intent2 = new Intent("android.intent.action.OPEN_DOCUMENT");
                    intent2.setType(com.bumptech.glide.b.b(input.a));
                    intent2.putExtra("android.intent.extra.ALLOW_MULTIPLE", true);
                    if (intent2.getType() != null) {
                        return intent2;
                    }
                    intent2.setType("*/*");
                    intent2.putExtra("android.intent.extra.MIME_TYPES", new String[]{"image/*", "video/*"});
                    return intent2;
                }
                ResolveInfo resolveInfoA = com.bumptech.glide.b.a(context);
                if (resolveInfoA == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                ActivityInfo activityInfo = resolveInfoA.activityInfo;
                Intent intent3 = new Intent("androidx.activity.result.contract.action.PICK_IMAGES");
                intent3.setClassName(activityInfo.applicationInfo.packageName, activityInfo.name);
                intent3.setType(com.bumptech.glide.b.b(input.a));
                int iMin2 = Math.min(5, input.b);
                if (iMin2 <= 1) {
                    throw new IllegalArgumentException("Max items must be greater than 1");
                }
                intent3.putExtra("androidx.activity.result.contract.extra.PICK_IMAGES_MAX", iMin2);
                input.c.getClass();
                intent3.putExtra("androidx.activity.result.contract.extra.PICK_IMAGES_LAUNCH_TAB", 1);
                intent3.putExtra("androidx.activity.result.contract.extra.PICK_IMAGES_IN_ORDER", false);
                return intent3;
            case 1:
                j input2 = (j) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input2, "input");
                int i2 = Build.VERSION.SDK_INT;
                if (i2 >= 33 || (i2 >= 30 && SdkExtensions.getExtensionVersion(30) >= 2)) {
                    Intent intent4 = new Intent("android.provider.action.PICK_IMAGES");
                    intent4.setType(com.bumptech.glide.b.b(input2.a));
                    input2.c.getClass();
                    intent4.putExtra("android.provider.extra.PICK_IMAGES_LAUNCH_TAB", 1);
                    return intent4;
                }
                Intrinsics.checkNotNullParameter(context, "context");
                if (com.bumptech.glide.b.a(context) == null) {
                    Intent intent5 = new Intent("android.intent.action.OPEN_DOCUMENT");
                    intent5.setType(com.bumptech.glide.b.b(input2.a));
                    if (intent5.getType() != null) {
                        return intent5;
                    }
                    intent5.setType("*/*");
                    intent5.putExtra("android.intent.extra.MIME_TYPES", new String[]{"image/*", "video/*"});
                    return intent5;
                }
                ResolveInfo resolveInfoA2 = com.bumptech.glide.b.a(context);
                if (resolveInfoA2 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                ActivityInfo activityInfo2 = resolveInfoA2.activityInfo;
                Intent intent6 = new Intent("androidx.activity.result.contract.action.PICK_IMAGES");
                intent6.setClassName(activityInfo2.applicationInfo.packageName, activityInfo2.name);
                intent6.setType(com.bumptech.glide.b.b(input2.a));
                input2.c.getClass();
                intent6.putExtra("androidx.activity.result.contract.extra.PICK_IMAGES_LAUNCH_TAB", 1);
                return intent6;
            case 2:
                String[] input3 = (String[]) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input3, "input");
                Intrinsics.checkNotNullParameter(input3, "input");
                Intent intentPutExtra = new Intent("androidx.activity.result.contract.action.REQUEST_PERMISSIONS").putExtra("androidx.activity.result.contract.extra.PERMISSIONS", input3);
                Intrinsics.checkNotNullExpressionValue(intentPutExtra, "Intent(ACTION_REQUEST_PE…EXTRA_PERMISSIONS, input)");
                return intentPutExtra;
            case 3:
                String input4 = (String) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input4, "input");
                String[] input5 = {input4};
                Intrinsics.checkNotNullParameter(input5, "input");
                Intent intentPutExtra2 = new Intent("androidx.activity.result.contract.action.REQUEST_PERMISSIONS").putExtra("androidx.activity.result.contract.extra.PERMISSIONS", input5);
                Intrinsics.checkNotNullExpressionValue(intentPutExtra2, "Intent(ACTION_REQUEST_PE…EXTRA_PERMISSIONS, input)");
                return intentPutExtra2;
            case 4:
                Intent input6 = (Intent) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input6, "input");
                return input6;
            case 5:
                IntentSenderRequest input7 = (IntentSenderRequest) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input7, "input");
                Intent intentPutExtra3 = new Intent("androidx.activity.result.contract.action.INTENT_SENDER_REQUEST").putExtra("androidx.activity.result.contract.extra.INTENT_SENDER_REQUEST", input7);
                Intrinsics.checkNotNullExpressionValue(intentPutExtra3, "Intent(ACTION_INTENT_SEN…NT_SENDER_REQUEST, input)");
                return intentPutExtra3;
            default:
                IntentSenderRequest intentSenderRequest = (IntentSenderRequest) obj;
                Intent intent7 = new Intent("androidx.activity.result.contract.action.INTENT_SENDER_REQUEST");
                Intent intent8 = intentSenderRequest.b;
                if (intent8 != null && (bundleExtra = intent8.getBundleExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE")) != null) {
                    intent7.putExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE", bundleExtra);
                    intent8.removeExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE");
                    if (intent8.getBooleanExtra("androidx.fragment.extra.ACTIVITY_OPTIONS_BUNDLE", false)) {
                        IntentSender intentSender = intentSenderRequest.a;
                        Intrinsics.checkNotNullParameter(intentSender, "intentSender");
                        intentSenderRequest = new IntentSenderRequest(intentSender, null, intentSenderRequest.c, intentSenderRequest.d);
                    }
                }
                intent7.putExtra("androidx.activity.result.contract.extra.INTENT_SENDER_REQUEST", intentSenderRequest);
                if (AbstractC1136h0.N(2)) {
                    intent7.toString();
                }
                return intent7;
        }
    }

    @Override // androidx.activity.result.contract.a
    public p b(Context context, Object obj) {
        switch (this.a) {
            case 0:
                j input = (j) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input, "input");
                return null;
            case 1:
                j input2 = (j) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input2, "input");
                return null;
            case 2:
                String[] input3 = (String[]) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input3, "input");
                if (input3.length == 0) {
                    return new p(V.c(), 1);
                }
                for (String str : input3) {
                    if (androidx.core.content.c.a(context, str) != 0) {
                        return null;
                    }
                }
                int iA = U.a(input3.length);
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                for (String str2 : input3) {
                    linkedHashMap.put(str2, Boolean.TRUE);
                }
                return new p(linkedHashMap, 1);
            case 3:
                String input4 = (String) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(input4, "input");
                if (androidx.core.content.c.a(context, input4) == 0) {
                    return new p(Boolean.TRUE, 1);
                }
                return null;
            default:
                return super.b(context, obj);
        }
    }

    @Override // androidx.activity.result.contract.a
    public final Object c(int i, Intent intent) {
        Object arrayList;
        List arrayList2;
        switch (this.a) {
            case 0:
                if (i != -1) {
                    intent = null;
                }
                if (intent != null) {
                    Intrinsics.checkNotNullParameter(intent, "<this>");
                    LinkedHashSet linkedHashSet = new LinkedHashSet();
                    Uri data = intent.getData();
                    if (data != null) {
                        linkedHashSet.add(data);
                    }
                    ClipData clipData = intent.getClipData();
                    if (clipData == null && linkedHashSet.isEmpty()) {
                        arrayList = K.a;
                    } else {
                        if (clipData != null) {
                            int itemCount = clipData.getItemCount();
                            for (int i2 = 0; i2 < itemCount; i2++) {
                                Uri uri = clipData.getItemAt(i2).getUri();
                                if (uri != null) {
                                    linkedHashSet.add(uri);
                                }
                            }
                        }
                        arrayList = new ArrayList(linkedHashSet);
                    }
                    if (arrayList != null) {
                    }
                }
                break;
            case 1:
                if (i != -1) {
                    intent = null;
                }
                if (intent != null) {
                    Uri data2 = intent.getData();
                    if (data2 == null) {
                        Intrinsics.checkNotNullParameter(intent, "<this>");
                        LinkedHashSet linkedHashSet2 = new LinkedHashSet();
                        Uri data3 = intent.getData();
                        if (data3 != null) {
                            linkedHashSet2.add(data3);
                        }
                        ClipData clipData2 = intent.getClipData();
                        if (clipData2 == null && linkedHashSet2.isEmpty()) {
                            arrayList2 = K.a;
                        } else {
                            if (clipData2 != null) {
                                int itemCount2 = clipData2.getItemCount();
                                for (int i3 = 0; i3 < itemCount2; i3++) {
                                    Uri uri2 = clipData2.getItemAt(i3).getUri();
                                    if (uri2 != null) {
                                        linkedHashSet2.add(uri2);
                                    }
                                }
                            }
                            arrayList2 = new ArrayList(linkedHashSet2);
                        }
                        break;
                    }
                }
                break;
            case 2:
                if (i == -1 && intent != null) {
                    String[] stringArrayExtra = intent.getStringArrayExtra("androidx.activity.result.contract.extra.PERMISSIONS");
                    int[] intArrayExtra = intent.getIntArrayExtra("androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS");
                    if (intArrayExtra != null && stringArrayExtra != null) {
                        ArrayList arrayList3 = new ArrayList(intArrayExtra.length);
                        for (int i4 : intArrayExtra) {
                            arrayList3.add(Boolean.valueOf(i4 == 0));
                        }
                        break;
                    } else {
                        break;
                    }
                }
                break;
            case 3:
                if (intent == null || i != -1) {
                    break;
                } else {
                    int[] intArrayExtra2 = intent.getIntArrayExtra("androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS");
                    boolean z = false;
                    if (intArrayExtra2 != null) {
                        int length = intArrayExtra2.length;
                        int i5 = 0;
                        while (true) {
                            if (i5 < length) {
                                if (intArrayExtra2[i5] == 0) {
                                    z = true;
                                } else {
                                    i5++;
                                }
                            }
                        }
                    }
                    break;
                }
                break;
        }
        return new ActivityResult(i, intent);
    }
}
