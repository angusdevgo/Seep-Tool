using System;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Interop;
using System.Windows.Media.Effects;
using Seep.Core;
using Seep.Modules;

namespace Seep.Suite
{
    public class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            // 全局未捕获异常守护，确保永远不闪退并给出友好提示
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try
                {
                    string err = e.ExceptionObject != null ? e.ExceptionObject.ToString() : "未知未处理异常";
                    File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                        string.Format("[{0}] UnhandledException: {1}\r\n\r\n", DateTime.Now, err));
                }
                catch { }
            };

            Application app = new Application();
            app.DispatcherUnhandledException += (s, e) =>
            {
                try
                {
                    File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                        string.Format("[{0}] DispatcherUnhandledException: {1}\r\n\r\n", DateTime.Now, e.Exception));
                    e.Handled = true; // 阻止崩溃闪退
                }
                catch { }
            };

            app.Run(new MainWindow());
        }
    }

    public class MainWindow : Window
    {
        #region DWM 沉浸式暗色标题栏 Win32 API

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            try
            {
                IntPtr hwnd = new WindowInteropHelper(this).Handle;
                int trueVal = 1;
                int res = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref trueVal, sizeof(int));
                if (res != 0)
                {
                    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref trueVal, sizeof(int));
                }
                int cornerPreference = 2; // DWMWCP_ROUND (Win11)
                DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref cornerPreference, sizeof(int));
            }
            catch { }
        }

        #endregion

        // 配色体系 (参考 IDM_Pro_Tool 1:1 标准暗夜黑曜石)
        private static readonly Color ColObsidian = Color.FromRgb(13, 17, 23);       // #0D1117 背景基色
        private static readonly Color ColSidebar = Color.FromRgb(22, 27, 34);        // #161B22 侧边栏
        private static readonly Color ColCard = Color.FromRgb(17, 24, 39);           // #111827 卡片底色
        private static readonly Color ColBorder = Color.FromRgb(45, 55, 72);         // #2D3748 边框线
        private static readonly Color ColBorderMuted = Color.FromRgb(48, 54, 61);    // #30363D 微弱边框
        private static readonly Color ColBtnDark = Color.FromRgb(33, 38, 45);        // #21262D 默认按钮
        private static readonly Color ColBtnDarkHover = Color.FromRgb(48, 54, 61);   // #30363D 悬浮态

        // 重音色系
        private static readonly Color ColBlue = Color.FromRgb(56, 189, 248);         // #38BDF8 天空蓝
        private static readonly Color ColBlueHover = Color.FromRgb(14, 165, 233);
        private static readonly Color ColBlueBadgeBg = Color.FromRgb(8, 47, 73);
        private static readonly Color ColBlueBadgeFg = Color.FromRgb(56, 189, 248);

        private static readonly Color ColGreen = Color.FromRgb(16, 185, 129);        // #10B981 翡翠绿
        private static readonly Color ColGreenHover = Color.FromRgb(5, 150, 105);
        private static readonly Color ColGreenBadgeBg = Color.FromRgb(6, 78, 59);
        private static readonly Color ColGreenBadgeFg = Color.FromRgb(52, 211, 153);

        private static readonly Color ColAmber = Color.FromRgb(245, 158, 11);        // #F59E0B 琥珀橙
        private static readonly Color ColAmberHover = Color.FromRgb(217, 119, 6);
        private static readonly Color ColAmberBadgeBg = Color.FromRgb(69, 26, 3);
        private static readonly Color ColAmberBadgeFg = Color.FromRgb(251, 191, 36);

        private static readonly Color ColRose = Color.FromRgb(244, 63, 94);          // #F43F5E 还原玫瑰红
        private static readonly Color ColRoseBadgeBg = Color.FromRgb(76, 5, 25);
        private static readonly Color ColRoseBadgeFg = Color.FromRgb(251, 113, 133);

        private static readonly Color ColPurple = Color.FromRgb(168, 85, 247);       // #A855F7 极客紫
        private static readonly Color ColPurpleBadgeBg = Color.FromRgb(59, 7, 100);
        private static readonly Color ColPurpleBadgeFg = Color.FromRgb(216, 180, 254);

        // 遥测面板标签
        private TextBlock lblStatPatched;
        private TextBlock lblStatOriginal;
        private TextBlock lblStatReady;
        private TextBlock lblStatMissing;
        private TextBlock lblStatTotal;

        // 选项卡与视图
        private Button tabBtn1;
        private Button tabBtn2;
        private Button tabBtn3;

        private ScrollViewer viewTargets;
        private ScrollViewer viewKeygen;
        private Border viewLog;

        // 底部状态
        private TextBlock lblGlobalStatus;
        private TextBox txtConsole;

        // 算号页面控件
        private TextBox txtListaryEmail;
        private TextBox txtListaryOutput;
        private TextBox txtSnipasteDays;
        private TextBox txtSnipasteOutput;

        // 目标矩阵数据
        public class TargetItemUI
        {
            public string Key;
            public string Name;
            public string Subtitle;
            public string ActionType; // "patch" or "gen"
            public string Path;
            public string State;
            public string Detail;

            public Border CardBorder;
            public TextBlock PathText;
            public Border BadgeBorder;
            public TextBlock BadgeText;
            public Button ActionBtn;
            public Button RevertBtn;
            public Button CheckBtn;
        }

        private List<TargetItemUI> _targets = new List<TargetItemUI>();

        public MainWindow()
        {
            this.Title = "Seep-Tool 客户端安全审计与集成工作台";
            this.Width = 1260;
            this.Height = 780;
            this.MinWidth = 1100;
            this.MinHeight = 720;
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            this.Background = new SolidColorBrush(ColObsidian);
            this.FontFamily = new FontFamily("Microsoft YaHei UI, Segoe UI");

            try
            {
                string iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_icon.png");
                if (!File.Exists(iconPath))
                    iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
                if (File.Exists(iconPath))
                {
                    this.Icon = BitmapFrame.Create(new Uri(iconPath, UriKind.Absolute));
                }
            }
            catch { }

            BuildUI();
            ScanTargetsAsync();
        }

        private void BuildUI()
        {
            Grid root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // 1. 左侧边栏 (Sidebar - 320px)
            Border sidebarBorder = new Border
            {
                Background = new SolidColorBrush(ColSidebar),
                BorderThickness = new Thickness(0, 0, 1, 0),
                BorderBrush = new SolidColorBrush(ColBorderMuted)
            };
            Grid.SetColumn(sidebarBorder, 0);
            sidebarBorder.Child = BuildSidebar();
            root.Children.Add(sidebarBorder);

            // 2. 右侧主工作区 (Main Panel)
            Grid mainPanel = BuildMainPanel();
            Grid.SetColumn(mainPanel, 1);
            root.Children.Add(mainPanel);

            this.Content = root;
        }

        #region 左侧边栏构建

        private UIElement BuildSidebar()
        {
            Grid sidebarGrid = new Grid();
            sidebarGrid.Margin = new Thickness(20, 24, 20, 20);
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Brand Header
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Status Dashboard
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Quick Actions
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Spacer
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Footer Badge

            // --- 1. Brand Logo & Title 区域 (Ann 图标) ---
            StackPanel brandBox = new StackPanel { Margin = new Thickness(0, 0, 0, 20) };
            StackPanel titleRow = new StackPanel { Orientation = Orientation.Horizontal };

            try
            {
                string iconImgPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app_icon.png");
                if (File.Exists(iconImgPath))
                {
                    Image brandImg = new Image
                    {
                        Source = new BitmapImage(new Uri(iconImgPath, UriKind.Absolute)),
                        Width = 36,
                        Height = 36,
                        Margin = new Thickness(0, 0, 12, 0),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    titleRow.Children.Add(brandImg);
                }
                else
                {
                    Border textLogo = new Border
                    {
                        Width = 36,
                        Height = 36,
                        CornerRadius = new CornerRadius(8),
                        Background = new SolidColorBrush(ColBlue),
                        Margin = new Thickness(0, 0, 12, 0),
                        Child = new TextBlock
                        {
                            Text = "Ann",
                            FontWeight = FontWeights.Bold,
                            FontSize = 14,
                            Foreground = Brushes.White,
                            HorizontalAlignment = HorizontalAlignment.Center,
                            VerticalAlignment = VerticalAlignment.Center
                        }
                    };
                    titleRow.Children.Add(textLogo);
                }
            }
            catch
            {
                titleRow.Children.Add(new TextBlock
                {
                    Text = "Ann",
                    FontSize = 20,
                    FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(ColBlue),
                    Margin = new Thickness(0, 0, 10, 0)
                });
            }

            StackPanel brandTextPanel = new StackPanel();
            brandTextPanel.Children.Add(new TextBlock
            {
                Text = "Seep-Tool",
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(240, 246, 252))
            });
            brandTextPanel.Children.Add(new TextBlock
            {
                Text = "Ann Unified Design // Native Pro",
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                Margin = new Thickness(0, 2, 0, 0)
            });
            titleRow.Children.Add(brandTextPanel);
            brandBox.Children.Add(titleRow);

            Grid.SetRow(brandBox, 0);
            sidebarGrid.Children.Add(brandBox);

            // --- 2. 状态看板 (Status Dashboard Card) ---
            Border statusCard = new Border
            {
                Background = new SolidColorBrush(ColCard),
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(14, 12, 14, 12),
                Margin = new Thickness(0, 0, 0, 18)
            };

            StackPanel statusPanel = new StackPanel();
            statusPanel.Children.Add(new TextBlock
            {
                Text = "📊 资产遥测与状态看板",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(201, 209, 217)),
                Margin = new Thickness(0, 0, 0, 10)
            });

            lblStatPatched = CreateStatusRow(statusPanel, "已激活：", "检测中...", ColGreen);
            lblStatOriginal = CreateStatusRow(statusPanel, "待修补原版：", "检测中...", ColAmber);
            lblStatReady = CreateStatusRow(statusPanel, "待激活：", "检测中...", ColBlue);
            lblStatMissing = CreateStatusRow(statusPanel, "未安装目标：", "检测中...", Color.FromRgb(139, 148, 158));
            lblStatTotal = CreateStatusRow(statusPanel, "纳入审计集：", "5 款目标", Color.FromRgb(240, 246, 252));

            statusCard.Child = statusPanel;
            Grid.SetRow(statusCard, 1);
            sidebarGrid.Children.Add(statusCard);

            // --- 3. 快速全局动作按钮 ---
            StackPanel actionPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
            actionPanel.Children.Add(new TextBlock
            {
                Text = "⚡ 快捷全局控制",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                Margin = new Thickness(0, 0, 0, 8)
            });

            Button btnScanAll = CreateActionButton("全部重新扫描 ↻", ColBtnDark, Color.FromRgb(201, 209, 217));
            btnScanAll.Click += (s, e) => ScanTargetsAsync();
            actionPanel.Children.Add(btnScanAll);

            Grid.SetRow(actionPanel, 2);
            sidebarGrid.Children.Add(actionPanel);

            // --- 4. 底部徽标 Badge ---
            Border footerCard = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(13, 17, 23)),
                CornerRadius = new CornerRadius(8),
                BorderBrush = new SolidColorBrush(ColBorderMuted),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(12, 10, 12, 10)
            };
            StackPanel footerStack = new StackPanel();
            footerStack.Children.Add(new TextBlock
            {
                Text = "🛡️ 沙盒合规研究模式",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(ColGreen)
            });
            footerStack.Children.Add(new TextBlock
            {
                Text = "CWE-602 决策旁路 · 0 侵入式白盒走查",
                FontSize = 9.5,
                Foreground = new SolidColorBrush(Color.FromRgb(110, 118, 129)),
                Margin = new Thickness(0, 2, 0, 0)
            });
            footerCard.Child = footerStack;

            Grid.SetRow(footerCard, 4);
            sidebarGrid.Children.Add(footerCard);

            return sidebarGrid;
        }

        private TextBlock CreateStatusRow(StackPanel parent, string label, string defVal, Color valColor)
        {
            Grid row = new Grid { Margin = new Thickness(0, 3, 0, 3) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            TextBlock lbl = new TextBlock
            {
                Text = label,
                FontSize = 11.5,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                VerticalAlignment = VerticalAlignment.Center
            };
            TextBlock val = new TextBlock
            {
                Text = defVal,
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = new SolidColorBrush(valColor),
                VerticalAlignment = VerticalAlignment.Center
            };

            Grid.SetColumn(lbl, 0);
            Grid.SetColumn(val, 1);
            row.Children.Add(lbl);
            row.Children.Add(val);
            parent.Children.Add(row);

            return val;
        }

        private Button CreateActionButton(string text, Color bg, Color fg)
        {
            Button btn = new Button
            {
                Content = text,
                Height = 36,
                Background = new SolidColorBrush(bg),
                Foreground = new SolidColorBrush(fg),
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Cursor = System.Windows.Input.Cursors.Hand
            };

            ControlTemplate template = new ControlTemplate(typeof(Button));
            FrameworkElementFactory borderFactory = new FrameworkElementFactory(typeof(Border));
            borderFactory.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
            borderFactory.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            borderFactory.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Button.BorderBrushProperty));
            borderFactory.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Button.BorderThicknessProperty));

            FrameworkElementFactory presenter = new FrameworkElementFactory(typeof(ContentPresenter));
            presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            borderFactory.AppendChild(presenter);

            template.VisualTree = borderFactory;
            btn.Template = template;
            return btn;
        }

        #endregion

        #region 右侧主工作区构建

        private Grid BuildMainPanel()
        {
            Grid main = new Grid();
            main.Margin = new Thickness(20, 20, 20, 16);
            main.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Top Tabview
            main.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Content
            main.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Bottom Status Bar

            // 1. 顶部现代化选项卡栏
            Border tabviewContainer = new Border
            {
                CornerRadius = new CornerRadius(10),
                Background = new SolidColorBrush(ColSidebar),
                BorderBrush = new SolidColorBrush(ColBorderMuted),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(4),
                Margin = new Thickness(0, 0, 0, 16)
            };
            Grid tabGrid = new Grid();
            tabGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tabGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            tabGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            tabBtn1 = CreateTabButton("🎯 目标状态与修补矩阵", true);
            tabBtn2 = CreateTabButton("🔐 授权码生成工坊", false);
            tabBtn3 = CreateTabButton("📝 实时安全审计终端", false);

            tabBtn1.Click += (s, e) => SwitchTab(0);
            tabBtn2.Click += (s, e) => SwitchTab(1);
            tabBtn3.Click += (s, e) => SwitchTab(2);

            Grid.SetColumn(tabBtn1, 0);
            Grid.SetColumn(tabBtn2, 1);
            Grid.SetColumn(tabBtn3, 2);

            tabGrid.Children.Add(tabBtn1);
            tabGrid.Children.Add(tabBtn2);
            tabGrid.Children.Add(tabBtn3);

            tabviewContainer.Child = tabGrid;
            Grid.SetRow(tabviewContainer, 0);
            main.Children.Add(tabviewContainer);

            // 2. 选项卡主体内容区
            Grid contentContainer = new Grid();
            Grid.SetRow(contentContainer, 1);

            viewTargets = BuildViewTargets();
            viewKeygen = BuildViewKeygen();
            viewLog = BuildViewLog();

            contentContainer.Children.Add(viewTargets);
            contentContainer.Children.Add(viewKeygen);
            contentContainer.Children.Add(viewLog);

            main.Children.Add(contentContainer);

            // 3. 底部状态栏
            Grid bottomBar = new Grid { Margin = new Thickness(2, 12, 2, 0) };
            bottomBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            bottomBar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            lblGlobalStatus = new TextBlock
            {
                Text = "🟢 引擎就绪 · 所有逆向与审计模块加载正常",
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(lblGlobalStatus, 0);
            bottomBar.Children.Add(lblGlobalStatus);

            TextBlock lblVer = new TextBlock
            {
                Text = "Seep-Tool Native Pro v2.2 // Ann Dark",
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(110, 118, 129)),
                VerticalAlignment = VerticalAlignment.Center
            };
            Grid.SetColumn(lblVer, 1);
            bottomBar.Children.Add(lblVer);

            Grid.SetRow(bottomBar, 2);
            main.Children.Add(bottomBar);

            return main;
        }

        private Button CreateTabButton(string text, bool isActive)
        {
            Button btn = new Button
            {
                Content = text,
                Height = 36,
                FontSize = 12,
                FontWeight = isActive ? FontWeights.Bold : FontWeights.Normal,
                Foreground = new SolidColorBrush(isActive ? Color.FromRgb(240, 246, 252) : Color.FromRgb(139, 148, 158)),
                Background = new SolidColorBrush(isActive ? ColCard : Colors.Transparent),
                BorderThickness = new Thickness(0),
                Cursor = System.Windows.Input.Cursors.Hand
            };

            ControlTemplate template = new ControlTemplate(typeof(Button));
            FrameworkElementFactory border = new FrameworkElementFactory(typeof(Border));
            border.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
            border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));

            FrameworkElementFactory content = new FrameworkElementFactory(typeof(ContentPresenter));
            content.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
            content.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
            border.AppendChild(content);

            template.VisualTree = border;
            btn.Template = template;
            return btn;
        }

        private void SwitchTab(int index)
        {
            viewTargets.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
            viewKeygen.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
            viewLog.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;

            tabBtn1.Background = new SolidColorBrush(index == 0 ? ColCard : Colors.Transparent);
            tabBtn1.Foreground = new SolidColorBrush(index == 0 ? Color.FromRgb(240, 246, 252) : Color.FromRgb(139, 148, 158));
            tabBtn1.FontWeight = index == 0 ? FontWeights.Bold : FontWeights.Normal;

            tabBtn2.Background = new SolidColorBrush(index == 1 ? ColCard : Colors.Transparent);
            tabBtn2.Foreground = new SolidColorBrush(index == 1 ? Color.FromRgb(240, 246, 252) : Color.FromRgb(139, 148, 158));
            tabBtn2.FontWeight = index == 1 ? FontWeights.Bold : FontWeights.Normal;

            tabBtn3.Background = new SolidColorBrush(index == 2 ? ColCard : Colors.Transparent);
            tabBtn3.Foreground = new SolidColorBrush(index == 2 ? Color.FromRgb(240, 246, 252) : Color.FromRgb(139, 148, 158));
            tabBtn3.FontWeight = index == 2 ? FontWeights.Bold : FontWeights.Normal;
        }

        #endregion

        #region 视图 1：目标矩阵卡片列表

        private ScrollViewer BuildViewTargets()
        {
            ScrollViewer sv = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };

            StackPanel panel = new StackPanel { Margin = new Thickness(0, 0, 6, 0) };

            string[][] defs = new string[][]
            {
                new string[] { "bandizip", "Bandizip 压缩工具 (Enterprise)", "DLL 热注入代理 · 自定义授权用户/邮箱 · 黑名单直通", "bandizip" },
                new string[] { "ut", "Uninstall Tool 卸载工具", "EXECryptor VM 共享内存 IPC 旁路 · IsRegistered 恒真", "patch" },
                new string[] { "seer", "Seer 极速文件预览", "双重决策分支走查 · 彻底消除 7 天倒计时与激活弹窗", "patch" },
                new string[] { "listary", "Listary Pro 效率搜索", "三哈希算法还原 · 192字符密钥 · 一键离线写入配置", "activate" },
                new string[] { "snipaste", "Snipaste 截图利器", "Ed25519 签名体系与 Blake2s-128 设备指纹逆向生成", "gen" },
                new string[] { "pixpin", "PixPin 截图贴图工具", "11 处会员特权判定走查 · 14 项 VIP 功能全量解锁 (CWE-602)", "patch" }
            };

            _targets.Clear();
            foreach (var d in defs)
            {
                var item = new TargetItemUI
                {
                    Key = d[0],
                    Name = d[1],
                    Subtitle = d[2],
                    ActionType = d[3],
                    Path = "检测中...",
                    State = "unknown"
                };

                Border card = BuildTargetCard(item);
                item.CardBorder = card;
                panel.Children.Add(card);
                _targets.Add(item);
            }

            sv.Content = panel;
            return sv;
        }

        private Border BuildTargetCard(TargetItemUI item)
        {
            Border card = new Border
            {
                Background = new SolidColorBrush(ColCard),
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(16, 14, 16, 14),
                Margin = new Thickness(0, 0, 0, 12)
            };

            Grid g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(44) });                     // 0: Icon
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });   // 1: Info
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(112) });                    // 2: 状态列
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });                     // 3: 检测列
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(92) });                     // 4: 修补/生成列
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });                     // 5: 还原列

            // ── 列 0: 图标 ──
            Border iconBorder = new Border
            {
                Width = 38,
                Height = 38,
                CornerRadius = new CornerRadius(8),
                Background = new SolidColorBrush(item.ActionType == "patch" ? ColBlueBadgeBg : ColPurpleBadgeBg),
                BorderBrush = new SolidColorBrush(item.ActionType == "patch" ? ColBlue : ColPurple),
                BorderThickness = new Thickness(1),
                VerticalAlignment = VerticalAlignment.Center
            };
            TextBlock iconTxt = new TextBlock
            {
                Text = item.Name.Substring(0, 1),
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(item.ActionType == "patch" ? ColBlue : ColPurple),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            iconBorder.Child = iconTxt;
            Grid.SetColumn(iconBorder, 0);
            g.Children.Add(iconBorder);

            // ── 列 1: 信息 ──
            StackPanel info = new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 10, 0) };
            info.Children.Add(new TextBlock
            {
                Text = item.Name,
                FontSize = 13.5,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(240, 246, 252))
            });
            info.Children.Add(new TextBlock
            {
                Text = item.Subtitle,
                FontSize = 10,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Foreground = new SolidColorBrush(Color.FromRgb(110, 118, 129)),
                Margin = new Thickness(0, 2, 0, 2)
            });

            item.PathText = new TextBlock
            {
                Text = "路径: 正在扫描...",
                FontSize = 9.5,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                FontFamily = new FontFamily("Consolas, Courier New")
            };
            info.Children.Add(item.PathText);

            Grid.SetColumn(info, 1);
            g.Children.Add(info);

            // ── 列 2: 状态列 (垂直居中，胶囊统一宽度对齐) ──
            item.BadgeBorder = new Border
            {
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(8, 5, 8, 5),
                Background = new SolidColorBrush(ColBorderMuted),
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            item.BadgeText = new TextBlock
            {
                Text = "检测中",
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                TextAlignment = TextAlignment.Center
            };
            item.BadgeBorder.Child = item.BadgeText;
            Grid.SetColumn(item.BadgeBorder, 2);
            g.Children.Add(item.BadgeBorder);

            // ── 列 3: 检测列 ──
            item.CheckBtn = CreateActionButton("检测", ColBtnDark, Color.FromRgb(201, 209, 217));
            item.CheckBtn.Width = 62;
            item.CheckBtn.Height = 30;
            item.CheckBtn.VerticalAlignment = VerticalAlignment.Center;
            item.CheckBtn.HorizontalAlignment = HorizontalAlignment.Center;
            item.CheckBtn.Click += (s, e) => CheckSingleTarget(item);
            Grid.SetColumn(item.CheckBtn, 3);
            g.Children.Add(item.CheckBtn);

            // ── 列 4: 修补 / 生成授权列 ──
            if (item.ActionType == "patch")
            {
                item.ActionBtn = CreateActionButton("修补 ⚡", ColBlue, Colors.White);
                item.ActionBtn.Click += (s, e) => PatchSingleTarget(item);
            }
            else if (item.ActionType == "bandizip")
            {
                item.ActionBtn = CreateActionButton("DLL 部署 🚀", ColBlue, Colors.White);
                item.ActionBtn.Click += (s, e) => ShowBandizipDeployDialog(item);
            }
            else if (item.ActionType == "gen")
            {
                item.ActionBtn = CreateActionButton("生成授权 🔑", ColPurple, Colors.White);
                item.ActionBtn.Click += (s, e) =>
                {
                    SwitchTab(1);
                    if (item.Key == "snipaste") GenerateSnipasteKey();
                };
            }
            else if (item.ActionType == "activate")
            {
                item.ActionBtn = CreateActionButton("一键激活 ⚡", ColGreen, Colors.White);
                item.ActionBtn.Click += (s, e) => OneClickListaryActivate(item);
            }
            item.ActionBtn.Width = 84;
            item.ActionBtn.Height = 30;
            item.ActionBtn.VerticalAlignment = VerticalAlignment.Center;
            item.ActionBtn.HorizontalAlignment = HorizontalAlignment.Center;
            Grid.SetColumn(item.ActionBtn, 4);
            g.Children.Add(item.ActionBtn);

            // ── 列 5: 还原列 ──
            if (item.ActionType == "patch" || item.ActionType == "bandizip")
            {
                if (item.ActionType == "bandizip")
                {
                    item.RevertBtn = CreateActionButton("还原 ↻", ColBtnDark, Color.FromRgb(244, 63, 94));
                    item.RevertBtn.Click += (s, e) => BandizipRemoveProxy(item);
                }
                else
                {
                    item.RevertBtn = CreateActionButton("还原 ↻", ColBtnDark, Color.FromRgb(244, 63, 94));
                    item.RevertBtn.Click += (s, e) => RevertSingleTarget(item);
                }
                item.RevertBtn.Width = 62;
                item.RevertBtn.Height = 30;
                item.RevertBtn.VerticalAlignment = VerticalAlignment.Center;
                item.RevertBtn.HorizontalAlignment = HorizontalAlignment.Center;
                Grid.SetColumn(item.RevertBtn, 5);
                g.Children.Add(item.RevertBtn);
            }
            else
            {
                // gen 类目标无还原操作，放一个占位保持列对齐
                var ph = new TextBlock
                {
                    Text = "—",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromRgb(60, 68, 80)),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(ph, 5);
                g.Children.Add(ph);
            }

            card.Child = g;
            return card;
        }

        private void UpdateTargetItemState(TargetItemUI item, string state, string path, string detail = null)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                item.State = state;
                item.Path = path;
                item.PathText.Text = string.IsNullOrEmpty(path) ? "路径: 未在本地检测到目标程序" : "路径: " + path;
                if (!string.IsNullOrEmpty(detail))
                    item.BadgeBorder.ToolTip = detail;

                if (state == "patched")
                {
                    item.BadgeBorder.Background = new SolidColorBrush(ColGreenBadgeBg);
                    item.BadgeText.Foreground = new SolidColorBrush(ColGreenBadgeFg);
                    item.BadgeText.Text = "已激活 ✓";
                    if (item.ActionBtn != null && item.ActionType == "patch")
                    {
                        item.ActionBtn.Content = "重新修补";
                        item.ActionBtn.Background = new SolidColorBrush(ColBtnDark);
                        item.ActionBtn.Foreground = new SolidColorBrush(Color.FromRgb(201, 209, 217));
                    }
                    if (item.RevertBtn != null)
                    {
                        item.RevertBtn.IsEnabled = true;
                        item.RevertBtn.Opacity = 1.0;
                    }
                }
                else if (state == "original")
                {
                    item.BadgeBorder.Background = new SolidColorBrush(ColAmberBadgeBg);
                    item.BadgeText.Foreground = new SolidColorBrush(ColAmberBadgeFg);
                    item.BadgeText.Text = "未激活/原版 ⚠️";
                    if (item.ActionBtn != null && item.ActionType == "patch")
                    {
                        item.ActionBtn.Content = "修补 ⚡";
                        item.ActionBtn.Background = new SolidColorBrush(ColBlue);
                        item.ActionBtn.Foreground = Brushes.White;
                    }
                    if (item.RevertBtn != null)
                    {
                        item.RevertBtn.IsEnabled = false;
                        item.RevertBtn.Opacity = 0.5;
                    }
                }
                else if (state == "ready")
                {
                    item.BadgeBorder.Background = new SolidColorBrush(ColPurpleBadgeBg);
                    item.BadgeText.Foreground = new SolidColorBrush(ColPurpleBadgeFg);
                    item.BadgeText.Text = "待激活 🔑";
                }
                else if (state == "missing")
                {
                    item.BadgeBorder.Background = new SolidColorBrush(Color.FromRgb(33, 38, 45));
                    item.BadgeText.Foreground = new SolidColorBrush(Color.FromRgb(110, 118, 129));
                    item.BadgeText.Text = "未安装 ✕";
                    if (item.RevertBtn != null)
                    {
                        item.RevertBtn.IsEnabled = false;
                        item.RevertBtn.Opacity = 0.5;
                    }
                }
                else
                {
                    item.BadgeBorder.Background = new SolidColorBrush(ColBorderMuted);
                    item.BadgeText.Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158));
                    item.BadgeText.Text = "待检测";
                }
            }));
        }

        #endregion

        #region 视图 2：授权码生成工坊

        private ScrollViewer BuildViewKeygen()
        {
            ScrollViewer sv = new ScrollViewer
            {
                Visibility = Visibility.Collapsed,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };

            StackPanel panel = new StackPanel { Margin = new Thickness(0, 0, 6, 0) };

            // 1. Listary Pro 授权卡片
            Border listaryCard = new Border
            {
                Background = new SolidColorBrush(ColCard),
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(18),
                Margin = new Thickness(0, 0, 0, 16)
            };
            StackPanel lp = new StackPanel();
            lp.Children.Add(new TextBlock
            {
                Text = "⚡ Listary Pro 离线许可证实时生成 (三哈希 96-Bit 算法全还原)",
                FontSize = 13.5,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(240, 246, 252)),
                Margin = new Thickness(0, 0, 0, 6)
            });
            lp.Children.Add(new TextBlock
            {
                Text = "无需打补丁。任意输入邮箱或直接点击生成，算法还原将自动完成 19 组校验段映射并自动复制。",
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                Margin = new Thickness(0, 0, 0, 14)
            });

            Grid lRow = new Grid();
            lRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            lRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });

            txtListaryEmail = new TextBox
            {
                Height = 36,
                Background = new SolidColorBrush(ColSidebar),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 7, 8, 7),
                FontSize = 12,
                Text = "seep_user@tool.local"
            };
            Grid.SetColumn(txtListaryEmail, 0);
            lRow.Children.Add(txtListaryEmail);

            Button btnGenListary = CreateActionButton("即时生成 ⚡", ColBlue, Colors.White);
            btnGenListary.Margin = new Thickness(10, 0, 0, 0);
            btnGenListary.Click += (s, e) => GenerateListaryKey();
            Grid.SetColumn(btnGenListary, 1);
            lRow.Children.Add(btnGenListary);

            lp.Children.Add(lRow);

            txtListaryOutput = new TextBox
            {
                Height = 70,
                Margin = new Thickness(0, 10, 0, 0),
                Background = new SolidColorBrush(Color.FromRgb(13, 17, 23)),
                Foreground = new SolidColorBrush(ColGreen),
                BorderBrush = new SolidColorBrush(ColBorderMuted),
                BorderThickness = new Thickness(1),
                FontFamily = new FontFamily("Consolas, Courier New"),
                FontSize = 10.5,
                TextWrapping = TextWrapping.Wrap,
                IsReadOnly = true,
                Padding = new Thickness(8)
            };
            lp.Children.Add(txtListaryOutput);

            Button btnDirectActivate = CreateActionButton("🚀 一键直接激活 Listary（自动写入并生效，推荐！）", ColGreen, Colors.White);
            btnDirectActivate.Height = 36;
            btnDirectActivate.Margin = new Thickness(0, 10, 0, 0);
            btnDirectActivate.Click += (s, e) =>
            {
                string em = txtListaryEmail.Text.Trim();
                if (string.IsNullOrEmpty(em)) em = "seep_user@tool.local";
                OneClickListaryActivateWithEmail(em);
            };
            lp.Children.Add(btnDirectActivate);

            listaryCard.Child = lp;
            panel.Children.Add(listaryCard);

            // 2. Snipaste 授权卡片
            Border snipasteCard = new Border
            {
                Background = new SolidColorBrush(ColCard),
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(18),
                Margin = new Thickness(0, 0, 0, 16)
            };
            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = "🔐 Snipaste 2.11.3 PRO 离线激活码签发 (Ed25519 + Blake2s-128)",
                FontSize = 13.5,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(240, 246, 252)),
                Margin = new Thickness(0, 0, 0, 6)
            });
            sp.Children.Add(new TextBlock
            {
                Text = "读取本机唯一硬件指纹 MachineGuid 动态生成期望设备码，并借助本地密钥对签发离线激活凭据。",
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(139, 148, 158)),
                Margin = new Thickness(0, 0, 0, 14)
            });

            Grid sRow = new Grid();
            sRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });

            txtSnipasteDays = new TextBox
            {
                Height = 36,
                Background = new SolidColorBrush(ColSidebar),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 7, 8, 7),
                FontSize = 12,
                Text = "366"
            };
            Grid.SetColumn(txtSnipasteDays, 0);
            sRow.Children.Add(txtSnipasteDays);

            Button btnGenSnipaste = CreateActionButton("签发激活码 🔑", ColPurple, Colors.White);
            btnGenSnipaste.Margin = new Thickness(10, 0, 0, 0);
            btnGenSnipaste.Click += (s, e) => GenerateSnipasteKey();
            Grid.SetColumn(btnGenSnipaste, 1);
            sRow.Children.Add(btnGenSnipaste);

            sp.Children.Add(sRow);

            txtSnipasteOutput = new TextBox
            {
                Height = 85,
                Margin = new Thickness(0, 10, 0, 0),
                Background = new SolidColorBrush(Color.FromRgb(13, 17, 23)),
                Foreground = new SolidColorBrush(ColPurpleBadgeFg),
                BorderBrush = new SolidColorBrush(ColBorderMuted),
                BorderThickness = new Thickness(1),
                FontFamily = new FontFamily("Consolas, Courier New"),
                FontSize = 10,
                TextWrapping = TextWrapping.Wrap,
                IsReadOnly = true,
                Padding = new Thickness(8)
            };
            sp.Children.Add(txtSnipasteOutput);

            snipasteCard.Child = sp;
            panel.Children.Add(snipasteCard);

            sv.Content = panel;
            return sv;
        }

        #endregion

        #region 视图 3：实时控制台日志

        private Border BuildViewLog()
        {
            Border b = new Border
            {
                Visibility = Visibility.Collapsed,
                Background = new SolidColorBrush(ColCard),
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(ColBorder),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(14)
            };

            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            Grid top = new Grid { Margin = new Thickness(0, 0, 0, 8) };
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            TextBlock title = new TextBlock
            {
                Text = "📟 逆向执行与安全审计输出日志",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(201, 209, 217))
            };
            Grid.SetColumn(title, 0);
            top.Children.Add(title);

            Button btnClear = CreateActionButton("清空日志 ✕", ColBtnDark, Color.FromRgb(139, 148, 158));
            btnClear.Height = 26;
            btnClear.Width = 70;
            btnClear.Click += (s, e) => txtConsole.Clear();
            Grid.SetColumn(btnClear, 1);
            top.Children.Add(btnClear);

            Grid.SetRow(top, 0);
            g.Children.Add(top);

            txtConsole = new TextBox
            {
                Background = new SolidColorBrush(Color.FromRgb(10, 14, 20)),
                Foreground = new SolidColorBrush(Color.FromRgb(165, 180, 252)),
                BorderBrush = new SolidColorBrush(ColBorderMuted),
                BorderThickness = new Thickness(1),
                FontFamily = new FontFamily("Consolas, Courier New"),
                FontSize = 11,
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(10)
            };
            Grid.SetRow(txtConsole, 1);
            g.Children.Add(txtConsole);

            b.Child = g;
            return b;
        }

        private void Log(string line)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    string ts = DateTime.Now.ToString("HH:mm:ss");
                    txtConsole.AppendText(string.Format("[{0}] {1}\r\n", ts, line));
                    txtConsole.ScrollToEnd();
                    lblGlobalStatus.Text = line;
                }
                catch { }
            }));
        }

        private Border _toastBorder;
        private TextBlock _toastText;
        private System.Windows.Threading.DispatcherTimer _toastTimer;

        private void ShowToast(string message, Color bgColor, Color fgColor)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    if (_toastBorder == null)
                    {
                        // 首次: 包装 Window 内容为 Grid 并挂 toast
                        var oldContent = this.Content as UIElement;
                        var wrapper = new Grid();
                        if (oldContent != null) wrapper.Children.Add(oldContent);

                        _toastBorder = new Border
                        {
                            CornerRadius = new CornerRadius(8),
                            Padding = new Thickness(18, 12, 18, 12),
                            BorderThickness = new Thickness(1),
                            HorizontalAlignment = HorizontalAlignment.Right,
                            VerticalAlignment = VerticalAlignment.Bottom,
                            Margin = new Thickness(0, 0, 28, 44),
                            Visibility = Visibility.Collapsed,
                            Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 18, ShadowDepth = 4, Opacity = 0.5 }
                        };
                        _toastText = new TextBlock { FontSize = 13, FontWeight = FontWeights.SemiBold };
                        _toastBorder.Child = _toastText;
                        wrapper.Children.Add(_toastBorder);
                        Panel.SetZIndex(_toastBorder, 9999);
                        this.Content = wrapper;
                    }

                    _toastBorder.Background = new SolidColorBrush(bgColor);
                    _toastBorder.BorderBrush = new SolidColorBrush(fgColor);
                    _toastText.Foreground = new SolidColorBrush(fgColor);
                    _toastText.Text = message;
                    _toastBorder.Visibility = Visibility.Visible;

                    if (_toastTimer == null)
                    {
                        _toastTimer = new System.Windows.Threading.DispatcherTimer();
                        _toastTimer.Interval = TimeSpan.FromMilliseconds(2800);
                        _toastTimer.Tick += (s2, e2) =>
                        {
                            _toastTimer.Stop();
                            if (_toastBorder != null) _toastBorder.Visibility = Visibility.Collapsed;
                        };
                    }
                    _toastTimer.Stop();
                    _toastTimer.Start();
                }
                catch { }
            }));
        }

        #endregion

        #region 后台业务逻辑驱动

        private void ScanTargetsAsync()
        {
            Log("[*] 正在并行检索本地目标路径与状态...");

            // 缓存秒显
            foreach (var item in _targets)
            {
                var cached = Seep.Core.DetectionCache.Get(item.Key);
                if (cached != null)
                    UpdateTargetItemState(item, cached.State, cached.Path, "[缓存] " + (cached.Detail ?? ""));
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                int patched = 0, original = 0, ready = 0, missing = 0;

                foreach (var item in _targets)
                {
                    string path;
                    var result = Seep.Core.DetectionEngine.Run(item.Key, out path);
                    UpdateTargetItemState(item, result.State, path, result.Detail);
                    foreach (var ev in result.Evidence) Log("    " + ev);

                    if (result.State == "patched") patched++;
                    else if (result.State == "original") original++;
                    else if (result.State == "ready") ready++;
                    else missing++;
                }

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    lblStatPatched.Text = patched.ToString();
                    lblStatOriginal.Text = original.ToString();
                    lblStatReady.Text = ready.ToString();
                    lblStatMissing.Text = missing.ToString();
                }));

                Log(string.Format("[+] 探测完成: 已激活 {0} / 待修补 {1} / 待激活 {2} / 未安装 {3}", patched, original, ready, missing));
            });
        }

        private void CheckSingleTarget(TargetItemUI item)
        {
            Log("=== 检测目标: " + item.Name + " ===");
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (item.CheckBtn != null) { item.CheckBtn.Content = "..."; item.CheckBtn.IsEnabled = false; }
            }));
            ThreadPool.QueueUserWorkItem(delegate
            {
                string path;
                var result = Seep.Core.DetectionEngine.Run(item.Key, out path);
                UpdateTargetItemState(item, result.State, path, result.Detail);
                foreach (var ev in result.Evidence) Log("    " + ev);

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (item.CheckBtn != null) { item.CheckBtn.Content = "检测"; item.CheckBtn.IsEnabled = true; }
                }));

                string stateDisplay = result.State;
                Color toastBg = ColCard, toastFg = Color.FromRgb(240, 246, 252);
                if (result.State == "patched") { stateDisplay = "已激活 ✓"; toastBg = ColGreenBadgeBg; toastFg = ColGreenBadgeFg; }
                else if (result.State == "original") { stateDisplay = "未激活/原版 ⚠️"; toastBg = ColAmberBadgeBg; toastFg = ColAmberBadgeFg; }
                else if (result.State == "ready") { stateDisplay = "待激活 🔑"; toastBg = ColPurpleBadgeBg; toastFg = ColPurpleBadgeFg; }
                else if (result.State == "missing") { stateDisplay = "未安装 ✕"; toastBg = Color.FromRgb(33, 38, 45); toastFg = Color.FromRgb(139, 148, 158); }

                Log("[OK] " + item.Name + " -> " + stateDisplay + " (" + result.Detail + ")");
                ShowToast(item.Name + "  |  " + stateDisplay, toastBg, toastFg);
            });
        }

        private void PatchSingleTarget(TargetItemUI item)
        {
            Log("=== 应用底层修补: " + item.Name + " ===");
            ThreadPool.QueueUserWorkItem(delegate
            {
                if (string.IsNullOrEmpty(item.Path) || item.State == "missing")
                {
                    Log("[-] 无法应用补丁: 目标未安装或未检测到路径");
                    return;
                }

                var l = new List<string>();
                bool ok = false;
                switch (item.Key)
                {
                    case "bandizip":
                        ok = BandizipModule.Patch(item.Path, l);
                        break;
                    case "ut":
                        ok = UninstallToolModule.Patch(item.Path, l);
                        if (ok) UninstallToolModule.WriteRegistration("Pro User", "2345678-ABCDEFG-HJKLMNP-QRSTUVW", l);
                        break;
                    case "seer":
                        ok = SeerModule.Patch(item.Path, l);
                        break;
                    case "pixpin":
                        ok = PixPinModule.Patch(item.Path, l);
                        break;
                }

                foreach (var line in l) Log(line);
                if (ok)
                {
                    Log("[OK] " + item.Name + " 修补成功！");
                    ShowToast(item.Name + "  |  已激活 ✓", ColGreenBadgeBg, ColGreenBadgeFg);
                }
                else
                {
                    Log("[-] " + item.Name + " 修补未完全执行");
                    ShowToast(item.Name + "  |  修补失败 ✕", ColRoseBadgeBg, ColRoseBadgeFg);
                }
                CheckSingleTarget(item);
            });
        }

        private void RevertSingleTarget(TargetItemUI item)
        {
            Log("=== 正在单独还原目标原版: " + item.Name + " ===");
            ThreadPool.QueueUserWorkItem(delegate
            {
                if (string.IsNullOrEmpty(item.Path) || item.State == "missing")
                {
                    Log("[-] 无法执行还原: 目标路径不存在");
                    return;
                }

                var l = new List<string>();
                bool ok = false;
                switch (item.Key)
                {
                    case "bandizip":
                        ok = BandizipModule.Revert(item.Path, l);
                        break;
                    case "ut":
                        ok = UninstallToolModule.Revert(item.Path, l);
                        break;
                    case "seer":
                        ok = SeerModule.Revert(item.Path, l);
                        break;
                    case "pixpin":
                        ok = PixPinModule.Revert(item.Path, l);
                        break;
                }

                foreach (var line in l) Log(line);
                if (ok)
                {
                    Log("[OK] " + item.Name + " 已还原为官方原版！");
                    ShowToast(item.Name + "  |  已还原原版 ↻", ColBlueBadgeBg, ColBlueBadgeFg);
                }
                else
                {
                    Log("[-] " + item.Name + " 还原未完全执行");
                    ShowToast(item.Name + "  |  还原失败 ✕", ColRoseBadgeBg, ColRoseBadgeFg);
                }
                CheckSingleTarget(item);
            });
        }

        #region Bandizip DLL Deploy & Custom License

        private void ShowBandizipDeployDialog(TargetItemUI item)
        {
            if (string.IsNullOrEmpty(item.Path))
            {
                Log("[-] 未定位到 Bandizip 安装目录");
                return;
            }
            var dlg = new Window { Title = "Bandizip DLL 代理部署", Width = 460, Height = 380,
                WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = this,
                Background = new SolidColorBrush(ColObsidian), ResizeMode = ResizeMode.NoResize, WindowStyle = WindowStyle.ToolWindow };
            ScrollViewer sv = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            StackPanel sp = new StackPanel { Margin = new Thickness(24) };
            sp.Children.Add(new TextBlock { Text = "DLL 热注入代理（推荐）", FontSize = 14, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(ColBlue), Margin = new Thickness(0,0,0,6) });
            sp.Children.Add(new TextBlock { Text = "部署 version.dll 代理至 Bandizip 目录，启动后自动解锁 Enterprise，并在关于对话框显示自定义授权。保留数字签名。", FontSize = 10.5, TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(139,148,158)), Margin = new Thickness(0,0,0,16) });
            sp.Children.Add(new TextBlock { Text = "授权用户名：", FontSize = 11, Foreground = new SolidColorBrush(Color.FromRgb(201,209,217)), Margin = new Thickness(0,0,0,4) });
            TextBox txtUser = new TextBox { Height = 32, Background = new SolidColorBrush(ColSidebar), Foreground = Brushes.White, BorderBrush = new SolidColorBrush(ColBorder), BorderThickness = new Thickness(1), Padding = new Thickness(8,6,8,6), FontSize = 12, Text = "AngusDevLab" };
            sp.Children.Add(txtUser);
            sp.Children.Add(new TextBlock { Text = "授权邮箱：", FontSize = 11, Foreground = new SolidColorBrush(Color.FromRgb(201,209,217)), Margin = new Thickness(0,10,0,4) });
            TextBox txtEmail = new TextBox { Height = 32, Background = new SolidColorBrush(ColSidebar), Foreground = Brushes.White, BorderBrush = new SolidColorBrush(ColBorder), BorderThickness = new Thickness(1), Padding = new Thickness(8,6,8,6), FontSize = 12, Text = "angusdevlab@vipuser.com" };
            sp.Children.Add(txtEmail);
            sp.Children.Add(new TextBlock { Text = "授权密钥：", FontSize = 11, Foreground = new SolidColorBrush(Color.FromRgb(201,209,217)), Margin = new Thickness(0,10,0,4) });
            TextBox txtKey = new TextBox { Height = 32, Background = new SolidColorBrush(ColSidebar), Foreground = Brushes.White, BorderBrush = new SolidColorBrush(ColBorder), BorderThickness = new Thickness(1), Padding = new Thickness(8,6,8,6), FontSize = 12, Text = "内部授权" };
            sp.Children.Add(txtKey);
            Button btn = CreateActionButton("立即部署并激活 Enterprise", ColBlue, Colors.White);
            btn.Height = 40; btn.Margin = new Thickness(0, 20, 0, 0);
            btn.Click += (s, e) => {
                dlg.Close();
                string u = txtUser.Text.Trim(), em = txtEmail.Text.Trim(), k = txtKey.Text.Trim();
                Log("=== Bandizip DLL 代理部署 ===");
                ThreadPool.QueueUserWorkItem(delegate {
                    var l = new List<string>();
                    bool ok = BandizipDllModule.DeployProxy(item.Path, u, em, k, l);
                    foreach (var line in l) Log(line);
                    Log(ok ? "[OK] 部署完成，启动 Bandizip 验证。" : "[-] 部署失败。");
                    CheckSingleTarget(item);
                });
            };
            sp.Children.Add(btn);
            sv.Content = sp; dlg.Content = sv; dlg.ShowDialog();
        }

        private void BandizipRemoveProxy(TargetItemUI item)
        {
            if (string.IsNullOrEmpty(item.Path)) { Log("[-] 未定位到 Bandizip 目录"); return; }
            Log("=== 移除 Bandizip DLL 代理并还原原版 ===");
            ThreadPool.QueueUserWorkItem(delegate {
                var l = new List<string>();
                bool ok = BandizipDllModule.RemoveProxy(item.Path, l);
                foreach (var line in l) Log(line);
                CheckSingleTarget(item);
            });
        }

        #endregion

                private void OneClickListaryActivateWithEmail(string email)
        {
            Log("=== Listary Pro 一键离线激活 ===");
            ThreadPool.QueueUserWorkItem(delegate
            {
                var l = new List<string>();
                bool ok = Seep.Modules.OneClickActivate.ActivateListary("Seep User", email, l);
                foreach (var line in l) Log(line);

                if (ok)
                {
                    Log("[OK] Listary Pro 离线激活成功！");
                    ShowToast("Listary Pro  |  已激活 ✓", ColGreenBadgeBg, ColGreenBadgeFg);
                    ScanTargetsAsync();
                }
                else
                {
                    Log("[-] Listary 激活失败");
                    ShowToast("Listary Pro  |  激活失败 ✕", ColRoseBadgeBg, ColRoseBadgeFg);
                }
            });
        }

        private void OneClickListaryActivate(TargetItemUI item)
        {
            Log("=== Listary Pro 一键离线激活 ===");
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (item.ActionBtn != null) { item.ActionBtn.Content = "激活中..."; item.ActionBtn.IsEnabled = false; }
            }));
            ThreadPool.QueueUserWorkItem(delegate
            {
                var l = new List<string>();
                bool ok = Seep.Modules.OneClickActivate.ActivateListary("Seep User", "seep_user@tool.local", l);
                foreach (var line in l) Log(line);

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (item.ActionBtn != null) { item.ActionBtn.Content = "一键激活 ⚡"; item.ActionBtn.IsEnabled = true; }
                }));

                if (ok)
                {
                    Log("[OK] Listary Pro 离线激活成功！");
                    ShowToast("Listary Pro  |  已激活 ✓ (离线写入)", ColGreenBadgeBg, ColGreenBadgeFg);
                    CheckSingleTarget(item);
                }
                else
                {
                    Log("[-] Listary 激活失败");
                    ShowToast("Listary Pro  |  激活失败 ✕", ColRoseBadgeBg, ColRoseBadgeFg);
                }
            });
        }

        private void GenerateListaryKey()
        {
            string email = txtListaryEmail.Text.Trim();
            if (string.IsNullOrEmpty(email)) email = ListaryModule.RandomEmail();

            string lic = ListaryModule.Generate(email);
            bool pass = ListaryModule.Verify(email, lic);

            txtListaryOutput.Text = lic; // 仅显示纯 192 字符密钥，防止用户框选复制带上前缀
            Clipboard.SetText(lic);

            Log(string.Format("[+] Listary 许可证签发成功 (自检 {0}): {1}", pass ? "PASS" : "FAIL", email));
        }

        private void GenerateSnipasteKey()
        {
            int days = 366;
            int.TryParse(txtSnipasteDays.Text.Trim(), out days);
            if (days <= 0) days = 366;

            var l = new List<string>();
            try
            {
                string code = SnipasteModule.BuildActivationCode("Seep User", "seep@tool.local", "Personal", days, "", l);
                txtSnipasteOutput.Text = code; // 仅显示纯激活码
                Clipboard.SetText(code);

                foreach (var line in l) Log(line);
                Log("[+] Snipaste 激活码签发成功并已复制到剪贴板！");
            }
            catch (Exception ex)
            {
                Log("[-] Snipaste 签发异常: " + ex.Message);
            }
        }

        #endregion
    }
}
