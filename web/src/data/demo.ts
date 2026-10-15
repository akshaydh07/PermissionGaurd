import type { AppPermission, ProtectedApp, RiskLevel } from "../types";

const permission = (
  name: string,
  group: string,
  severity: RiskLevel,
  purposeFit: AppPermission["purposeFit"],
  explanation: string,
  recommendation: string,
  confidence = 0.94,
): AppPermission => ({
  name,
  group,
  severity,
  confidence,
  explanation,
  purposeFit,
  recommendation,
});

export const demoApps: ProtectedApp[] = [
  {
    id: "com.trailhead",
    name: "Trailhead",
    publisher: "Northstar Mobility",
    category: "Navigation",
    initials: "T",
    tint: "mint",
    score: 18,
    risk: "Low",
    lastScanned: "Today, 9:41 AM",
    permissions: [
      permission(
        "Precise location",
        "Location",
        "Medium",
        "Expected",
        "Precise location can reveal movement patterns. It aligns with turn-by-turn navigation, but should only be available while you use the app.",
        "Keep location access set to “While using the app” unless you rely on a specific background navigation feature.",
      ),
      permission(
        "Network access",
        "Network",
        "Low",
        "Expected",
        "Network access supports live maps and traffic updates.",
        "Review the app's privacy notice for how location data is processed.",
      ),
    ],
  },
  {
    id: "com.pocketlens",
    name: "Pocket Lens",
    publisher: "Studio Luma",
    category: "Photography",
    initials: "P",
    tint: "blue",
    score: 34,
    risk: "Medium",
    lastScanned: "Today, 9:38 AM",
    permissions: [
      permission(
        "Camera",
        "Camera",
        "Medium",
        "Expected",
        "Camera access is consistent with a photography app. A manifest request does not prove the camera is actively used.",
        "Allow camera access only when you are taking or editing a photo.",
      ),
      permission(
        "Photo library",
        "Files & media",
        "Medium",
        "Expected",
        "The app can request access to images stored on your device. It also declares network access, so review any sync or upload feature.",
        "Prefer selected-photo access and check whether cloud sync is enabled.",
        0.82,
      ),
      permission(
        "Network access",
        "Network",
        "Low",
        "Expected",
        "Network access may support sharing or backup. The permission alone cannot establish what data is sent.",
        "Check the app's privacy settings before enabling automatic uploads.",
      ),
    ],
  },
  {
    id: "com.morningnote",
    name: "Morning Note",
    publisher: "Fern Labs",
    category: "Productivity",
    initials: "M",
    tint: "peach",
    score: 8,
    risk: "Low",
    lastScanned: "Today, 9:34 AM",
    permissions: [
      permission(
        "Network access",
        "Network",
        "Low",
        "Expected",
        "Network access can be used for sync across your devices.",
        "Disable sync if you prefer notes to stay on this device.",
      ),
    ],
  },
  {
    id: "com.pulsewell",
    name: "Pulsewell",
    publisher: "Wellwise Digital",
    category: "Health & fitness",
    initials: "W",
    tint: "lavender",
    score: 61,
    risk: "High",
    lastScanned: "Today, 9:29 AM",
    permissions: [
      permission(
        "Microphone",
        "Microphone",
        "High",
        "Review",
        "Microphone access is not clearly explained by this app's stated fitness purpose.",
        "Review the app's features and restrict microphone access in Android settings if you do not use voice features.",
        0.71,
      ),
      permission(
        "Background activity",
        "Background",
        "Medium",
        "Review",
        "Background execution together with microphone access is a review indicator, not evidence that audio is recorded.",
        "Check whether an always-on feature is enabled and turn it off if unnecessary.",
        0.7,
      ),
      permission(
        "Precise location",
        "Location",
        "Medium",
        "Expected",
        "Precise location may support route tracking, but can reveal sensitive movement patterns.",
        "Use approximate or while-in-use access when those options meet your needs.",
      ),
    ],
  },
  {
    id: "com.quickcalc",
    name: "Quick Calc",
    publisher: "Plainview Apps",
    category: "Utilities",
    initials: "Q",
    tint: "sky",
    score: 73,
    risk: "High",
    lastScanned: "Today, 9:22 AM",
    permissions: [
      permission(
        "Contacts",
        "Personal data",
        "High",
        "Review",
        "Contacts access is difficult to justify for a calculator and may expose personal information.",
        "If contact features are not part of your workflow, change this permission to “Don't allow” in Android settings.",
        0.88,
      ),
      permission(
        "Precise location",
        "Location",
        "High",
        "Review",
        "Location is not expected for a basic calculator and can reveal where you spend time.",
        "Review the app's purpose and restrict location access if it is not needed.",
        0.91,
      ),
      permission(
        "Network access",
        "Network",
        "Low",
        "Review",
        "Network access is not needed for basic offline calculations; this signal alone does not explain app behavior.",
        "Check whether online features or ads are enabled, and review the privacy policy.",
      ),
    ],
  },
  {
    id: "com.cityweather",
    name: "City Weather",
    publisher: "Blueglass",
    category: "Weather",
    initials: "C",
    tint: "gold",
    score: 23,
    risk: "Low",
    lastScanned: "Yesterday, 8:12 PM",
    permissions: [
      permission(
        "Approximate location",
        "Location",
        "Medium",
        "Expected",
        "Approximate location can personalize local forecasts with less precision than GPS.",
        "Use approximate location if it provides forecasts accurately enough.",
      ),
      permission(
        "Network access",
        "Network",
        "Low",
        "Expected",
        "Network access is expected for retrieving forecast data.",
        "Review the developer's data-sharing disclosure.",
      ),
    ],
  },
];

export type DemoAlert = {
  id: string;
  appId: string;
  appName: string;
  title: string;
  detail: string;
  severity: RiskLevel;
  time: string;
  read: boolean;
};

export const demoAlerts: DemoAlert[] = [
  {
    id: "alert-1",
    appId: "com.quickcalc",
    appName: "Quick Calc",
    title: "Contacts access may be unnecessary",
    detail: "A calculator requests access to your contacts.",
    severity: "High",
    time: "9:22 AM",
    read: false,
  },
  {
    id: "alert-2",
    appId: "com.pulsewell",
    appName: "Pulsewell",
    title: "Review microphone and background access",
    detail: "Together, these declarations deserve a closer look.",
    severity: "High",
    time: "9:29 AM",
    read: false,
  },
  {
    id: "alert-3",
    appId: "com.pocketlens",
    appName: "Pocket Lens",
    title: "Photo access and network access",
    detail: "Review selected-photo access and optional image sync.",
    severity: "Medium",
    time: "9:38 AM",
    read: true,
  },
];

export const demoHistory = [
  { date: "Today, 9:41 AM", app: "Trailhead", source: "Installed app", score: 18, risk: "Low" as const },
  { date: "Today, 9:38 AM", app: "Pocket Lens", source: "Installed app", score: 34, risk: "Medium" as const },
  { date: "Today, 9:34 AM", app: "Morning Note", source: "Installed app", score: 8, risk: "Low" as const },
  { date: "Today, 9:29 AM", app: "Pulsewell", source: "Installed app", score: 61, risk: "High" as const },
  { date: "Today, 9:22 AM", app: "Quick Calc", source: "Installed app", score: 73, risk: "High" as const },
  { date: "Yesterday, 8:12 PM", app: "City Weather", source: "Installed app", score: 23, risk: "Low" as const },
];

export const riskDistribution = [
  { name: "Low", value: 3, color: "#43d6bd" },
  { name: "Medium", value: 1, color: "#e7b86b" },
  { name: "High", value: 2, color: "#f07f79" },
];

export const activityTrend = [
  { day: "Mon", scans: 2 },
  { day: "Tue", scans: 3 },
  { day: "Wed", scans: 2 },
  { day: "Thu", scans: 4 },
  { day: "Fri", scans: 3 },
  { day: "Sat", scans: 5 },
  { day: "Sun", scans: 6 },
];
