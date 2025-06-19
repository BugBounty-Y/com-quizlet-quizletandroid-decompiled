package com.braze.configuration;

import android.content.Context;
import android.content.res.Resources;
import androidx.work.impl.utils.q;
import com.braze.X;
import com.braze.Y;
import com.braze.support.BrazeLogger;
import com.braze.support.PackageUtils;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes.dex */
public class CachedConfigurationProvider {
    public static final c Companion = new c();
    private final Map<String, Object> configurationCache;
    private Context context;
    private final String resourcePackageName;
    private RuntimeAppConfigurationProvider runtimeAppConfigurationProvider;
    private boolean shouldUseConfigurationCache;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public CachedConfigurationProvider(Context context) {
        this(context, false, null, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final String getFallbackConfigKey(String str) {
        if (StringsKt.G(str, "braze", false)) {
            return D.o(str, "braze", "appboy", false);
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getResourceConfigurationValue$lambda$1(String str, Object obj) {
        return "Using resources value for key: '" + str + "' and value: '" + obj + '\'';
    }

    private final int getResourceIdentifier(String str, d dVar) {
        if (str == null) {
            return 0;
        }
        return this.context.getResources().getIdentifier(str, dVar.a, this.resourcePackageName);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getRuntimeConfigurationValue$lambda$0(String str, Object obj) {
        return "Using runtime override value for key: '" + str + "' and value: '" + obj + '\'';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String readResourceValue$lambda$2(String str, Object obj) {
        return "Primary key '" + str + "' had no identifier. No secondary key to read resource value. Returning default value: '" + obj + '\'';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String readResourceValue$lambda$3() {
        return "Caught exception retrieving resource value";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String readResourceValue$lambda$4(d dVar, String str, Object obj) {
        StringBuilder sb = new StringBuilder("Unable to find the xml ");
        sb.append(dVar);
        sb.append(" configuration value with primary key '");
        sb.append(str);
        sb.append("'. Using default value '");
        return android.support.v4.media.session.a.s(sb, obj, "'.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String resetCache$lambda$5() {
        return "Resetting cached configuration";
    }

    public final boolean getBooleanValue(String primaryKey, boolean z) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        Object configurationValue = getConfigurationValue(d.d, primaryKey, Boolean.valueOf(z));
        Intrinsics.e(configurationValue, "null cannot be cast to non-null type kotlin.Boolean");
        return ((Boolean) configurationValue).booleanValue();
    }

    public final Integer getColorValue(String primaryKey) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        return (Integer) getConfigurationValue(d.c, primaryKey, null);
    }

    public final Map<String, Object> getConfigurationCache() {
        return this.configurationCache;
    }

    public final Object getConfigurationValue(d type, String key, Object obj) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(key, "key");
        return (this.shouldUseConfigurationCache && this.configurationCache.containsKey(key)) ? this.configurationCache.get(key) : this.runtimeAppConfigurationProvider.containsKey(key) ? getRuntimeConfigurationValue(type, key, obj) : getResourceConfigurationValue(type, key, obj);
    }

    public final int getDrawableValue(String primaryKey, int i) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        Object configurationValue = getConfigurationValue(d.f, primaryKey, Integer.valueOf(i));
        Intrinsics.e(configurationValue, "null cannot be cast to non-null type kotlin.Int");
        return ((Integer) configurationValue).intValue();
    }

    public final int getIntValue(String primaryKey, int i) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        Object configurationValue = getConfigurationValue(d.b, primaryKey, Integer.valueOf(i));
        Intrinsics.e(configurationValue, "null cannot be cast to non-null type kotlin.Int");
        return ((Integer) configurationValue).intValue();
    }

    public final Object getResourceConfigurationValue(d type, String key, Object obj) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(key, "key");
        Object resourceValue = readResourceValue(type, key, obj);
        this.configurationCache.put(key, resourceValue);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new X(key, 2, resourceValue), 7, (Object) null);
        return resourceValue;
    }

    public final RuntimeAppConfigurationProvider getRuntimeAppConfigurationProvider() {
        return this.runtimeAppConfigurationProvider;
    }

    public final Object getRuntimeConfigurationValue(d type, String key, Object obj) {
        Object objValueOf;
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(key, "key");
        int iOrdinal = type.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            objValueOf = Integer.valueOf(obj == null ? this.runtimeAppConfigurationProvider.getIntValue(key, 0) : this.runtimeAppConfigurationProvider.getIntValue(key, ((Integer) obj).intValue()));
        } else if (iOrdinal == 2) {
            RuntimeAppConfigurationProvider runtimeAppConfigurationProvider = this.runtimeAppConfigurationProvider;
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Boolean");
            objValueOf = Boolean.valueOf(runtimeAppConfigurationProvider.getBooleanValue(key, ((Boolean) obj).booleanValue()));
        } else if (iOrdinal == 3) {
            objValueOf = this.runtimeAppConfigurationProvider.getStringValue(key, (String) obj);
        } else if (iOrdinal == 4) {
            objValueOf = Integer.valueOf(getResourceIdentifier(this.runtimeAppConfigurationProvider.getStringValue(key, ""), d.f));
        } else {
            if (iOrdinal != 5) {
                throw new NoWhenBranchMatchedException();
            }
            RuntimeAppConfigurationProvider runtimeAppConfigurationProvider2 = this.runtimeAppConfigurationProvider;
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.Set<kotlin.String?>");
            objValueOf = runtimeAppConfigurationProvider2.getStringSetValue(key, (Set) obj);
        }
        this.configurationCache.put(key, objValueOf);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new X(key, 3, objValueOf), 7, (Object) null);
        return objValueOf;
    }

    public final Set<String> getStringSetValue(String primaryKey, Set<String> set) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        Object configurationValue = getConfigurationValue(d.g, primaryKey, set);
        return configurationValue == null ? set : (Set) configurationValue;
    }

    public final String getStringValue(String primaryKey, String str) {
        Intrinsics.checkNotNullParameter(primaryKey, "primaryKey");
        return (String) getConfigurationValue(d.e, primaryKey, str);
    }

    public final Object getValueFromResources(d type, int i) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(type, "type");
        Resources resources = this.context.getResources();
        int iOrdinal = type.ordinal();
        if (iOrdinal == 0) {
            return Integer.valueOf(resources.getInteger(i));
        }
        if (iOrdinal == 1) {
            return Integer.valueOf(resources.getColor(i));
        }
        if (iOrdinal == 2) {
            return Boolean.valueOf(resources.getBoolean(i));
        }
        if (iOrdinal == 3) {
            String string = resources.getString(i);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            return string;
        }
        if (iOrdinal == 4) {
            return Integer.valueOf(i);
        }
        if (iOrdinal != 5) {
            throw new NoWhenBranchMatchedException();
        }
        String[] stringArray = resources.getStringArray(i);
        Intrinsics.checkNotNullExpressionValue(stringArray, "getStringArray(...)");
        return new HashSet(B.j(Arrays.copyOf(stringArray, stringArray.length)));
    }

    public final Object readResourceValue(d type, String key, Object obj) {
        int resourceIdentifier;
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            resourceIdentifier = getResourceIdentifier(key, type);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(27), 4, (Object) null);
        }
        if (resourceIdentifier != 0) {
            return getValueFromResources(type, resourceIdentifier);
        }
        String fallbackConfigKey = getFallbackConfigKey(key);
        if (fallbackConfigKey == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new X(key, 4, obj), 7, (Object) null);
            return obj;
        }
        int resourceIdentifier2 = getResourceIdentifier(fallbackConfigKey, type);
        if (resourceIdentifier2 != 0) {
            return getValueFromResources(type, resourceIdentifier2);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new q(type, key, obj, 2), 7, (Object) null);
        return obj;
    }

    public final void resetCache$android_sdk_base_release() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new Y(28), 7, (Object) null);
        this.configurationCache.clear();
    }

    public CachedConfigurationProvider(Context context, boolean z, RuntimeAppConfigurationProvider runtimeAppConfigurationProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(runtimeAppConfigurationProvider, "runtimeAppConfigurationProvider");
        this.context = context;
        this.shouldUseConfigurationCache = z;
        this.runtimeAppConfigurationProvider = runtimeAppConfigurationProvider;
        Map<String, Object> mapSynchronizedMap = Collections.synchronizedMap(new HashMap());
        Intrinsics.checkNotNullExpressionValue(mapSynchronizedMap, "synchronizedMap(...)");
        this.configurationCache = mapSynchronizedMap;
        this.resourcePackageName = PackageUtils.getResourcePackageName(this.context);
    }

    public /* synthetic */ CachedConfigurationProvider(Context context, boolean z, RuntimeAppConfigurationProvider runtimeAppConfigurationProvider, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i & 2) != 0 ? true : z, (i & 4) != 0 ? new RuntimeAppConfigurationProvider(context) : runtimeAppConfigurationProvider);
    }
}
