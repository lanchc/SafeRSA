Pod::Spec.new do |s|
  s.name             = 'SafeRSA'
  s.version          = '2.1.0'
  s.summary          = 'A short description of SafeRSA.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = 'Swift版本#加密算法封装'

  s.homepage         = 'https://github.com/懒虫/SafeRSA'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { '懒虫' => '11534516+lanchc@users.noreply.github.com' }
  s.source           = { :git => 'https://github.com/懒虫/SafeRSA.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.swift_version = '5.0'

  s.ios.deployment_target = '10.0'

  s.source_files = 'SafeRSA/**/*'
  
  # s.resource_bundles = {
  #   'SafeRSA' => ['SafeRSA/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
