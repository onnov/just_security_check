<?php

namespace JustSecurityCheck\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class RunLock extends Command
{
    protected function configure()
    {
        $this->setName('run:check')
            ->setAliases(['r', 'run'])
            ->setDescription('Check for security advisories for the packages in your composer.json')
            ->addOption('dev', 'D', InputOption::VALUE_NONE, 'If require-dev should be checked as well');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $dir = getcwd() . '/';

        if (!file_exists($dir . 'composer.lock')) {
            $output->write('No composer.lock file found.');

            return 1;
        }

        $composerLock = file_get_contents($dir . 'composer.lock');

        $json = json_decode($composerLock, true);

        if (!array_key_exists('packages', $json)) {
            $output->write('There is no require.' . PHP_EOL);
            return 1;
        }

        if ($input->getOption('dev')) {
            if (!array_key_exists('packages-dev', $json)) {
                $output->write('There is no require-dev.' . PHP_EOL);
                return 1;
            }
        }

        $counter = 0;
        $counterPart = 0;
        $max = 50;
        $fullPackages = [];
        foreach ($json['packages'] as $package) {
            $key = $package['name'];
            $value = mb_eregi_replace("[^0-9.]", '', $package['version']);
            $fullPackages[$counterPart][$key] = $value;

            if (++$counter === $max) {
                ++$counterPart;
                $counter = 0;
            }
        }

        if ($input->getOption('dev')) {
            foreach ($json['packages-dev'] as $package) {
                $key = $package['name'];
                $value = mb_eregi_replace("[^0-9.]", '', $package['version']);
                $fullPackages[$key] = $value;

                if (++$counter === $max) {
                    ++$counterPart;
                    $counter = 0;
                }
            }
        }

        $packages = [];
        $advisoriesAll = [];
        foreach ($fullPackages as $partPackages) {
            $responseJson = file_get_contents(
                'https://packagist.org/api/security-advisories/?packages[]=' .
                implode('&packages[]=', array_keys($partPackages))
            );

            $packages = array_merge($packages, $partPackages);
            $advisoriesAll = array_merge($advisoriesAll, json_decode($responseJson, true)['advisories']);
        }

        $result = [];
        foreach ($advisoriesAll as $key => $advisories) {
            $curVersion = $this->getFullVersion($packages[$key]);
            foreach ($advisories as $advisory) {
                if (array_key_exists('affectedVersions', $advisory)) {
                    $next = false;
                    $ranges = explode('|', $advisory['affectedVersions']);
                    foreach ($ranges as $range) {
                        $par1 = false;
                        $par2 = false;
                        foreach (explode(',', $range) as $versionStr) {
                            if (strpos($versionStr, '>=') !== false) {
                                $versionStr = str_replace('>=', '', $versionStr);
                                $par1 = ($curVersion >= $this->getFullVersion($versionStr));
                            } else if (strpos($versionStr, '>') !== false) {
                                $versionStr = str_replace('>', '', $versionStr);
                                $par1 = ($curVersion > $this->getFullVersion($versionStr));
                            } else if (strpos($versionStr, '<=') !== false) {
                                $versionStr = str_replace('<=', '', $versionStr);
                                $par2 = ($curVersion <= $this->getFullVersion($versionStr));
                            } else if (strpos($versionStr, '<') !== false) {
                                $versionStr = str_replace('<', '', $versionStr);
                                $par2 = ($curVersion < $this->getFullVersion($versionStr));
                            }

                            if ($par1 && $par2) {
                                $result[$key] = $packages[$key];
                                break;
                            }
                        }
                        if ($par1 && $par2) {
                            $next = true;
                            break;
                        }
                    }
                    if ($next) {
                        break;
                    }
                }
            }
        }

        $vln = count($result);

        $vlnFormat = '<fg=green>' . $vln . ' packages</>';
        $res = 0;
        if ($vln > 0) {
            $res = 1;
            foreach ($result as $key => $val) {
                $output->writeln('<fg=green>' . $key . '</> <fg=red>(v' . $val . ')</>');
            }
            $vlnFormat = '<fg=red>' . $vln . ' packages</>';
        }
        $output->writeln($vlnFormat . ' have known vulnerabilities.');

        return $res;
    }

    /**
     * @param string $str
     * @return int
     */
    private function getFullVersion($str)
    {
        $versionArr = explode('.', $str);

        $versionArr = array_pad($versionArr, 4, '000');

        $versionFull = '';
        foreach ($versionArr as & $item) {
            $versionFull .= str_pad($item, 3, '0');
        }

        return (int)$versionFull;
    }
}