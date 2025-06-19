package com.google.ads.conversiontracking;

import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.FeatureInfo;
import android.content.pm.InstrumentationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PermissionGroupInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.UserHandle;
import java.util.List;

/* loaded from: classes2.dex */
public class d {
    public final a a;

    public static class a extends ContextWrapper {
        public final b a;
        public final e b;

        public a(Context context) {
            super(context);
            this.a = new b(context);
            Resources resources = context.getResources();
            this.b = new e(resources.getAssets(), resources.getDisplayMetrics(), resources.getConfiguration());
        }

        @Override // android.content.ContextWrapper, android.content.Context
        public final PackageManager getPackageManager() {
            return this.a;
        }

        @Override // android.content.ContextWrapper, android.content.Context
        public final Resources getResources() {
            return this.b;
        }
    }

    public static class b extends PackageManager {
        public final Context a;
        public final PackageManager b;

        public b(Context context) {
            this.a = context;
            this.b = context.getPackageManager();
        }

        @Override // android.content.pm.PackageManager
        public final void addPackageToPreferred(String str) {
            this.b.addPackageToPreferred(str);
        }

        @Override // android.content.pm.PackageManager
        public final boolean addPermission(PermissionInfo permissionInfo) {
            return this.b.addPermission(permissionInfo);
        }

        @Override // android.content.pm.PackageManager
        public final boolean addPermissionAsync(PermissionInfo permissionInfo) {
            return this.b.addPermissionAsync(permissionInfo);
        }

        @Override // android.content.pm.PackageManager
        public final void addPreferredActivity(IntentFilter intentFilter, int i, ComponentName[] componentNameArr, ComponentName componentName) {
            this.b.addPreferredActivity(intentFilter, i, componentNameArr, componentName);
        }

        @Override // android.content.pm.PackageManager
        public final String[] canonicalToCurrentPackageNames(String[] strArr) {
            return this.b.canonicalToCurrentPackageNames(strArr);
        }

        @Override // android.content.pm.PackageManager
        public final int checkPermission(String str, String str2) {
            return this.b.checkPermission(str, str2);
        }

        @Override // android.content.pm.PackageManager
        public final int checkSignatures(int i, int i2) {
            return this.b.checkSignatures(i, i2);
        }

        @Override // android.content.pm.PackageManager
        public final void clearPackagePreferredActivities(String str) {
            this.b.clearPackagePreferredActivities(str);
        }

        @Override // android.content.pm.PackageManager
        public final String[] currentToCanonicalPackageNames(String[] strArr) {
            return this.b.currentToCanonicalPackageNames(strArr);
        }

        @Override // android.content.pm.PackageManager
        public final void extendVerificationTimeout(int i, int i2, long j) {
            this.b.extendVerificationTimeout(i, i2, j);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityBanner(Intent intent) {
            return this.b.getActivityBanner(intent);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityIcon(Intent intent) {
            return this.b.getActivityIcon(intent);
        }

        @Override // android.content.pm.PackageManager
        public final ActivityInfo getActivityInfo(ComponentName componentName, int i) {
            return this.b.getActivityInfo(componentName, i);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityLogo(Intent intent) {
            return this.b.getActivityLogo(intent);
        }

        @Override // android.content.pm.PackageManager
        public final List getAllPermissionGroups(int i) {
            return this.b.getAllPermissionGroups(i);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationBanner(ApplicationInfo applicationInfo) {
            return this.b.getApplicationBanner(applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final int getApplicationEnabledSetting(String str) {
            return this.b.getApplicationEnabledSetting(str);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationIcon(String str) {
            return this.b.getApplicationIcon(str);
        }

        @Override // android.content.pm.PackageManager
        public final ApplicationInfo getApplicationInfo(String str, int i) throws PackageManager.NameNotFoundException {
            ApplicationInfo applicationInfo = this.b.getApplicationInfo(str, i);
            if (str.equals(this.a.getPackageName()) && (i & 128) == 128) {
                if (applicationInfo.metaData == null) {
                    applicationInfo.metaData = new Bundle();
                }
                applicationInfo.metaData.putInt("com.google.android.gms.version", 4323000);
            }
            return applicationInfo;
        }

        @Override // android.content.pm.PackageManager
        public final CharSequence getApplicationLabel(ApplicationInfo applicationInfo) {
            return this.b.getApplicationLabel(applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationLogo(String str) {
            return this.b.getApplicationLogo(str);
        }

        @Override // android.content.pm.PackageManager
        public final int getComponentEnabledSetting(ComponentName componentName) {
            return this.b.getComponentEnabledSetting(componentName);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getDefaultActivityIcon() {
            return this.b.getDefaultActivityIcon();
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getDrawable(String str, int i, ApplicationInfo applicationInfo) {
            return this.b.getDrawable(str, i, applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final List getInstalledApplications(int i) {
            return this.b.getInstalledApplications(i);
        }

        @Override // android.content.pm.PackageManager
        public final List getInstalledPackages(int i) {
            return this.b.getInstalledPackages(i);
        }

        @Override // android.content.pm.PackageManager
        public final String getInstallerPackageName(String str) {
            return this.b.getInstallerPackageName(str);
        }

        @Override // android.content.pm.PackageManager
        public final InstrumentationInfo getInstrumentationInfo(ComponentName componentName, int i) {
            return this.b.getInstrumentationInfo(componentName, i);
        }

        @Override // android.content.pm.PackageManager
        public final Intent getLaunchIntentForPackage(String str) {
            return this.b.getLaunchIntentForPackage(str);
        }

        @Override // android.content.pm.PackageManager
        public final Intent getLeanbackLaunchIntentForPackage(String str) {
            return this.b.getLeanbackLaunchIntentForPackage(str);
        }

        @Override // android.content.pm.PackageManager
        public final String getNameForUid(int i) {
            return this.b.getNameForUid(i);
        }

        @Override // android.content.pm.PackageManager
        public final int[] getPackageGids(String str) {
            return this.b.getPackageGids(str);
        }

        @Override // android.content.pm.PackageManager
        public final PackageInfo getPackageInfo(String str, int i) {
            return this.b.getPackageInfo(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final PackageInstaller getPackageInstaller() {
            return this.b.getPackageInstaller();
        }

        @Override // android.content.pm.PackageManager
        public final String[] getPackagesForUid(int i) {
            return this.b.getPackagesForUid(i);
        }

        @Override // android.content.pm.PackageManager
        public final List getPackagesHoldingPermissions(String[] strArr, int i) {
            return this.b.getPackagesHoldingPermissions(strArr, i);
        }

        @Override // android.content.pm.PackageManager
        public final PermissionGroupInfo getPermissionGroupInfo(String str, int i) {
            return this.b.getPermissionGroupInfo(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final PermissionInfo getPermissionInfo(String str, int i) {
            return this.b.getPermissionInfo(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final int getPreferredActivities(List list, List list2, String str) {
            return this.b.getPreferredActivities(list, list2, str);
        }

        @Override // android.content.pm.PackageManager
        public final List getPreferredPackages(int i) {
            return this.b.getPreferredPackages(i);
        }

        @Override // android.content.pm.PackageManager
        public final ProviderInfo getProviderInfo(ComponentName componentName, int i) {
            return this.b.getProviderInfo(componentName, i);
        }

        @Override // android.content.pm.PackageManager
        public final ActivityInfo getReceiverInfo(ComponentName componentName, int i) {
            return this.b.getReceiverInfo(componentName, i);
        }

        @Override // android.content.pm.PackageManager
        public final Resources getResourcesForActivity(ComponentName componentName) {
            return this.b.getResourcesForActivity(componentName);
        }

        @Override // android.content.pm.PackageManager
        public final Resources getResourcesForApplication(String str) {
            return this.b.getResourcesForApplication(str);
        }

        @Override // android.content.pm.PackageManager
        public final ServiceInfo getServiceInfo(ComponentName componentName, int i) {
            return this.b.getServiceInfo(componentName, i);
        }

        @Override // android.content.pm.PackageManager
        public final FeatureInfo[] getSystemAvailableFeatures() {
            return this.b.getSystemAvailableFeatures();
        }

        @Override // android.content.pm.PackageManager
        public final String[] getSystemSharedLibraryNames() {
            return this.b.getSystemSharedLibraryNames();
        }

        @Override // android.content.pm.PackageManager
        public final CharSequence getText(String str, int i, ApplicationInfo applicationInfo) {
            return this.b.getText(str, i, applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getUserBadgedDrawableForDensity(Drawable drawable, UserHandle userHandle, Rect rect, int i) {
            return this.b.getUserBadgedDrawableForDensity(drawable, userHandle, rect, i);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getUserBadgedIcon(Drawable drawable, UserHandle userHandle) {
            return this.b.getUserBadgedIcon(drawable, userHandle);
        }

        @Override // android.content.pm.PackageManager
        public final CharSequence getUserBadgedLabel(CharSequence charSequence, UserHandle userHandle) {
            return this.b.getUserBadgedLabel(charSequence, userHandle);
        }

        @Override // android.content.pm.PackageManager
        public final XmlResourceParser getXml(String str, int i, ApplicationInfo applicationInfo) {
            return this.b.getXml(str, i, applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final boolean hasSystemFeature(String str) {
            return this.b.hasSystemFeature(str);
        }

        @Override // android.content.pm.PackageManager
        public final boolean isSafeMode() {
            return this.b.isSafeMode();
        }

        @Override // android.content.pm.PackageManager
        public final List queryBroadcastReceivers(Intent intent, int i) {
            return this.b.queryBroadcastReceivers(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryContentProviders(String str, int i, int i2) {
            return this.b.queryContentProviders(str, i, i2);
        }

        @Override // android.content.pm.PackageManager
        public final List queryInstrumentation(String str, int i) {
            return this.b.queryInstrumentation(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryIntentActivities(Intent intent, int i) {
            return this.b.queryIntentActivities(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryIntentActivityOptions(ComponentName componentName, Intent[] intentArr, Intent intent, int i) {
            return this.b.queryIntentActivityOptions(componentName, intentArr, intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryIntentContentProviders(Intent intent, int i) {
            return this.b.queryIntentContentProviders(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryIntentServices(Intent intent, int i) {
            return this.b.queryIntentServices(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final List queryPermissionsByGroup(String str, int i) {
            return this.b.queryPermissionsByGroup(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final void removePackageFromPreferred(String str) {
            this.b.removePackageFromPreferred(str);
        }

        @Override // android.content.pm.PackageManager
        public final void removePermission(String str) {
            this.b.removePermission(str);
        }

        @Override // android.content.pm.PackageManager
        public final ResolveInfo resolveActivity(Intent intent, int i) {
            return this.b.resolveActivity(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final ProviderInfo resolveContentProvider(String str, int i) {
            return this.b.resolveContentProvider(str, i);
        }

        @Override // android.content.pm.PackageManager
        public final ResolveInfo resolveService(Intent intent, int i) {
            return this.b.resolveService(intent, i);
        }

        @Override // android.content.pm.PackageManager
        public final void setApplicationEnabledSetting(String str, int i, int i2) {
            this.b.setApplicationEnabledSetting(str, i, i2);
        }

        @Override // android.content.pm.PackageManager
        public final void setComponentEnabledSetting(ComponentName componentName, int i, int i2) {
            this.b.setComponentEnabledSetting(componentName, i, i2);
        }

        @Override // android.content.pm.PackageManager
        public final void setInstallerPackageName(String str, String str2) {
            this.b.setInstallerPackageName(str, str2);
        }

        @Override // android.content.pm.PackageManager
        public final void verifyPendingInstall(int i, int i2) {
            this.b.verifyPendingInstall(i, i2);
        }

        @Override // android.content.pm.PackageManager
        public final int checkSignatures(String str, String str2) {
            return this.b.checkSignatures(str, str2);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityBanner(ComponentName componentName) {
            return this.b.getActivityBanner(componentName);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityIcon(ComponentName componentName) {
            return this.b.getActivityIcon(componentName);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getActivityLogo(ComponentName componentName) {
            return this.b.getActivityLogo(componentName);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationBanner(String str) {
            return this.b.getApplicationBanner(str);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationIcon(ApplicationInfo applicationInfo) {
            return this.b.getApplicationIcon(applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final Drawable getApplicationLogo(ApplicationInfo applicationInfo) {
            return this.b.getApplicationLogo(applicationInfo);
        }

        @Override // android.content.pm.PackageManager
        public final Resources getResourcesForApplication(ApplicationInfo applicationInfo) {
            return this.b.getResourcesForApplication(applicationInfo);
        }
    }

    public d(Context context) {
        this.a = new a(context);
    }
}
